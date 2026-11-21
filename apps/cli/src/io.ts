import { Context, type Effect } from "effect";

import type { AgentProfile } from "./agent-gate.ts";
import type { CliError } from "./errors.ts";

export type { AgentProfile };

export interface CliIoShape {
  readonly log: (line: string) => Effect.Effect<void>;
  readonly logError: (line: string) => Effect.Effect<void>;
  readonly readStdin: Effect.Effect<Uint8Array, CliError>;
  readonly promptLine: (input: {
    readonly prompt: string;
    readonly secret?: boolean;
  }) => Effect.Effect<string, CliError>;
  readonly envVar: (name: string) => string | undefined;
  readonly agentProfile: () => AgentProfile;
  readonly stderrIsTerminal: () => boolean;
  readonly colorEnabled: () => boolean;
  readonly openBrowser: (url: string) => Effect.Effect<boolean>;
}

export class CliIo extends Context.Service<CliIo, CliIoShape>()("cli/CliIo") {}
