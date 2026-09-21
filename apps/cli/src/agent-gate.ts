// 値の表示可否の判定(ADR-0016 決定 7 — 一次境界を TTY に置く fail-closed の 2 層)。
//
// **deny-list だけでは足りない理由**: 「既知のエージェントの環境変数リスト」に
// 一致したら拒否する方式は、境界の定義が上流のリストに依存し、
// リストに載っていない新しいエージェント・自作ハーネス・CI・ログ収集経路は
// **素通りする**(fail-open)。環境変数の標準化は未確定
// (`AGENT` と `AI_AGENT` が併存、各社独自変数が乱立)なので、
// 「リストが常に正しい」という前提そのものが持たない。
//
// よって、値を見てよいのは**人間が対話端末で実行したとき**だけ、という
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

/**
 * 鍵素材・capability の表示 / 入力に使う3チャネルTTYゲート。
 * stderrへ出す経路もあるため、値表示のstdin+stdout境界より1チャネル厳しい。
 */
export function ensureSensitiveTerminalAllowed(input: {
  readonly agent: AgentProfile;
  readonly stderrIsTerminal: boolean;
  readonly agentError: string;
  readonly terminalError: string;
}): Effect.Effect<void, CliError, Stdio.Stdio> {
  return Effect.gen(function* () {
    if (input.agent.isAgent) {
      return yield* Effect.fail(cliError(input.agentError));
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal || !input.stderrIsTerminal) {
      return yield* Effect.fail(cliError(input.terminalError));
    }
  });
}

/**
 * 一次境界(stdin と stdout が端末か)に落ちた側を名指しする(DP5 追補 G)。
 * 「両方が端末ではない」と一括りに言うと、`| less` を外せばよいのか
 * ヒアドキュメントをやめればよいのかが分からない。判定の意味論は不変で、
 * 文面の材料に判定結果をそのまま使うだけ(新しい検査は足していない)。
 */
export function describeNonTerminal(input: {
  readonly stdinIsTerminal: boolean;
  readonly stdoutIsTerminal: boolean;
}): string {
  if (!input.stdinIsTerminal && !input.stdoutIsTerminal) {
    return "neither stdin nor stdout is an interactive terminal";
  }
  return input.stdinIsTerminal
    ? "stdout is not an interactive terminal"
    : "stdin is not an interactive terminal";
}

/**
 * 既知エージェントを検出したときの拒否文(名前は診断のためだけに出す)。
 * 文面の順は「何が拒否されたか → なぜ → どうすればよいか」(DP5 裁定 G —
 * 判定の意味論は不変)。
 */
function agentRejection(name: string | undefined): CliError {
  const detected = name === undefined ? "" : ` (${name})`;
  return cliError(
    `Refused to display values: an AI agent environment was detected${detected}. Values are shown only to a person at an interactive terminal, so they never land in an agent's transcript. Run this command yourself in a terminal`,
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
          `Refused to display values: ${describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal })}. Values are shown only to a person at a terminal (pipes, redirects, CI, and AI agents are refused), so they never land in a file or a log. Run this command yourself in a terminal, without redirecting its input or output`,
        ),
      );
    }
  },
);

/**
 * 儀式の 2 層ゲートの共通形(ADR-0016 決定 7 と同じ材料: 既知エージェントの検出 →
 * stdin / stdout が端末か)。拒否文は儀式ごとに与える(何が拒否されたか → なぜ →
 * どうすればよいか)。`agentRefusal` は検出名の括弧書き(空文字あり)を受ける。
 */
export function ensureHumanCeremonyAllowed(input: {
  readonly agentRefusal: (detected: string) => string;
  readonly terminalRefusal: (reason: string) => string;
}): Effect.Effect<void, CliError, Stdio.Stdio> {
  return Effect.gen(function* () {
    const agent = yield* AgentProfileRef;
    if (agent.isAgent) {
      const detected = agent.name === undefined ? "" : ` (${agent.name})`;
      return yield* Effect.fail(cliError(input.agentRefusal(detected)));
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal) {
      return yield* Effect.fail(
        cliError(input.terminalRefusal(describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal }))),
      );
    }
  });
}

/**
 * `maruhi device approve` の儀式ゲート(設計録 dk-design.md §9 K4-6 — ADR-0016 決定 7 の
 * 2 層と同じ材料): 承認は人が別端末から運んだ FP を照合する行為で、エージェント環境や
 * 非対話(パイプ・CI)では成立しない。指紋帳の一致も人の yes を代替しない(K4-3)。
 */
export const ensureDeviceApproveAllowed: Effect.Effect<void, CliError, Stdio.Stdio> =
  ensureHumanCeremonyAllowed({
    agentRefusal: (detected) =>
      `Refused to approve a device: an AI agent environment was detected${detected}. Approving a device key adds a signer to every project you are a member of, so it is done only by a person at an interactive terminal who compared the fingerprint with the new device. Run \`maruhi device approve\` yourself in a terminal`,
    terminalRefusal: (reason) =>
      `Refused to approve a device: ${reason}. Approving a device key is done only by a person at a terminal (pipes, redirects, CI, and AI agents are refused). Run \`maruhi device approve\` yourself in a terminal, without redirecting its input or output`,
  });
