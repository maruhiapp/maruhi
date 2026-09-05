// CLI の入出力境界(Effect サービス)。
//
// テストが出力の捕捉・stdin の注入・エージェント検出のシミュレートを行えるよう、
// プロセスグローバル(console / process.stdin / 環境変数)への直接アクセスを
// この境界に集約する。本番実装は live.ts。
//
// 絶対規則: log / logError に平文値・鍵素材を渡さない(呼び出し側の責務。
// 値の表示は pull --show の明示経路のみで、人間の対話端末以外では拒否される
// — agent-gate.ts)。

import { Context, type Effect } from "effect";

import type { AgentProfile } from "./agent-gate.ts";
import type { CliError } from "./errors.ts";

/**
 * Agent-detection profile.
 *
 * 実体は agent-gate.ts(検出は live.ts が std-env で行う)。値の表示可否の
 * **一次境界は TTY** で、この profile は二次層 — 据え置きの deny-list ゲート
 * (invite / member / server grant。ADR-0016 決定 7 の裁定)が
 * `agentProfile()` として読む。
 */
export type { AgentProfile };

/** I/O boundary for CLI commands (stdout / stderr / stdin / env / agent detection). */
export interface CliIoShape {
  readonly log: (line: string) => Effect.Effect<void>;
  readonly logError: (line: string) => Effect.Effect<void>;
  /** Reads stdin to EOF (push values arrive here, never via argv). */
  readonly readStdin: Effect.Effect<Uint8Array, CliError>;
  /**
   * Reads one interactive line (recovery-code entry / save confirmation).
   * `secret` requests no-echo input on a TTY; off-TTY input falls back to a
   * plain line read. Fails when no input is available (EOF / 非対話環境).
   */
  readonly promptLine: (input: {
    readonly prompt: string;
    readonly secret?: boolean;
  }) => Effect.Effect<string, CliError>;
  readonly envVar: (name: string) => string | undefined;
  readonly agentProfile: () => AgentProfile;
  /** Recovery code uses stderr; this keeps redirect detection behind the I/O service boundary. */
  readonly stderrIsTerminal: () => boolean;
  /**
   * Whether stderr notices may use ANSI colors (notice.ts). 本番は
   * `shouldUseColor`(stderr が端末か + NO_COLOR / FORCE_COLOR / TERM)、
   * テストは既定で無色。色を付けるのは接頭辞だけで stdout には付けない。
   */
  readonly colorEnabled: () => boolean;
  /**
   * Opens `url` in the default browser (best effort; returns whether the
   * attempt was started). CLI ログインのブラウザ脚(AUTH_SPEC §4-1 (2))の
   * UX 分岐専用 — 呼び出し側が「対話端末 × 非エージェント」のときだけ呼ぶ。
   * 失敗しても login は表示 + ポーリングで完走する(縮退経路は 1 本)。
   */
  readonly openBrowser: (url: string) => Effect.Effect<boolean>;
}

export class CliIo extends Context.Service<CliIo, CliIoShape>()("cli/CliIo") {}
