import { Context, Effect, Stdio } from "effect";

import { cliError, type CliError } from "./errors.ts";

export interface AgentProfile {
  readonly isAgent: boolean;
  readonly name?: string | undefined;
}

export class AgentProfileRef extends Context.Reference<AgentProfile>("cli/AgentProfile", {
  defaultValue: (): AgentProfile => ({ isAgent: false }),
}) {}

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

function agentRejection(name: string | undefined): CliError {
  const detected = name === undefined ? "" : ` (${name})`;
  return cliError(
    `Refused to display values: an AI agent environment was detected${detected}. Values are shown only to a person at an interactive terminal, so they never land in an agent's transcript. Run this command yourself in a terminal`,
  );
}

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
      return yield* Effect.fail(
        cliError(
          `Refused to display values: ${describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal })}. Values are shown only to a person at a terminal (pipes, redirects, CI, and AI agents are refused), so they never land in a file or a log. Run this command yourself in a terminal, without redirecting its input or output`,
        ),
      );
    }
  },
);

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

export const ensureDeviceApproveAllowed: Effect.Effect<void, CliError, Stdio.Stdio> =
  ensureHumanCeremonyAllowed({
    agentRefusal: (detected) =>
      `Refused to approve a device: an AI agent environment was detected${detected}. Approving a device key adds a signer to every project you are a member of, so it is done only by a person at an interactive terminal who compared the fingerprint with the new device. Run \`maruhi device approve\` yourself in a terminal`,
    terminalRefusal: (reason) =>
      `Refused to approve a device: ${reason}. Approving a device key is done only by a person at a terminal (pipes, redirects, CI, and AI agents are refused). Run \`maruhi device approve\` yourself in a terminal, without redirecting its input or output`,
  });

export const ensurePlainRunAllowed: Effect.Effect<void, CliError, Stdio.Stdio> =
  ensureHumanCeremonyAllowed({
    agentRefusal: (detected) =>
      `Refused to run with the real values: an AI agent environment was detected${detected} and this repository has a proxy config (maruhi.proxy.json). Run the command without --plain so the values are brokered, or run it yourself in a terminal`,
    terminalRefusal: (reason) =>
      `Refused to run with the real values: ${reason}, and this repository has a proxy config (maruhi.proxy.json). --plain is allowed only to a person at an interactive terminal (pipes, redirects, CI, and AI agents are refused); run the command without --plain so the values are brokered`,
  });
