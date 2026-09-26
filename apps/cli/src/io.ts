// The CLI's I/O boundary (an Effect service).
//
// Concentrates direct access to process globals (console /
// process.stdin / environment variables) behind this boundary so
// tests can capture output, inject stdin, and simulate agent
// detection. The production implementation is live.ts.
//
// Absolute rule: never pass plaintext values or key material to log /
// logError (the caller's responsibility. Value display is only via
// the explicit `pull --show` path and is refused off a human
// interactive terminal — agent-gate.ts).

import { Context, type Effect } from "effect";

import type { AgentProfile } from "./agent-gate.ts";
import type { CliError } from "./errors.ts";

/**
 * Agent-detection profile.
 *
 * The substance lives in agent-gate.ts (detection is done by live.ts
 * via std-env). The **primary boundary** for value-display permission
 * is the TTY; this profile is the secondary layer — the kept-as-is
 * deny-list gates (invite / member / server grant; the ruling of
 * ADR-0016 decision 7) read it via `agentProfile()`.
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
   * plain line read. Fails when no input is available (EOF / non-interactive environment).
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
   * Whether stderr notices may use ANSI colors (notice.ts). In
   * production, `shouldUseColor` (whether stderr is a terminal +
   * NO_COLOR / FORCE_COLOR / TERM); tests default to no color. Only
   * prefixes are colored — never stdout.
   */
  readonly colorEnabled: () => boolean;
  /**
   * Opens `url` in the default browser (best effort; returns whether the
   * attempt was started). Solely for the UX branch of the CLI
   * login's browser leg (AUTH_SPEC §4-1 (2)) — the caller invokes it
   * only for "interactive terminal × non-agent". login completes via
   * display + polling even on failure (the fallback path is one).
   */
  readonly openBrowser: (url: string) => Effect.Effect<boolean>;
}

export class CliIo extends Context.Service<CliIo, CliIoShape>()("cli/CliIo") {}
