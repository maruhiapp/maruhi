import { Effect } from "effect";
import { Argument, Command } from "effect/cli";

import { AGENT_COMMAND_REQUIRED, agentOp, agentStatusOp, parseKeyTtl } from "../agent.ts";
import { singleValued } from "./flags.ts";
import { commandAfterTerminator } from "./shared.ts";

export const agentConfig = {
  "key-ttl": singleValued(
    "key-ttl",
    "Forget this device's key this long after it is stored (e.g. 30m, 2h); the token stays. Default: keep it until the command exits",
  ),
  command: Argument.String("command").pipe(
    Argument.withDescription(
      "The command to run inside the agent session, written after `--` (usually a shell)",
    ),
    Argument.atLeast(1),
    Argument.filter(
      (command) => (command[0] ?? "").trim() !== "",
      () => AGENT_COMMAND_REQUIRED,
    ),
  ),
};

export const agentStatusConfig = {};

export function makeAgentCommands(onExitCode: (code: number) => void) {
  const agentStatus = Command.make("status", agentStatusConfig, () => agentStatusOp()).pipe(
    Command.withDescription(
      "Show what the current agent session holds (entry names only, never values)",
    ),
  );

  const agent = Command.make(
    "agent",
    agentConfig,
    Effect.fn("commands-agent.agent")(function* (values) {
      const command = yield* commandAfterTerminator(values.command);
      const keyTtl =
        values["key-ttl"] === undefined
          ? undefined
          : { ms: yield* parseKeyTtl(values["key-ttl"]), text: values["key-ttl"] };
      onExitCode(yield* agentOp({ command, keyTtl }));
    }),
  ).pipe(
    Command.withDescription(
      "Hold the token and this device's key in memory for the lifetime of a command, for machines without an OS keychain (ssh-agent style; nothing is written to disk). Write the command after `--`; `agent status` shows what the session holds",
    ),
    Command.withSubcommands([agentStatus]),
  );

  return agent;
}
