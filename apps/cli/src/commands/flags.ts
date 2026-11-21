import { EnvironmentIdSchema, ProjectIdSchema, UserIdSchema } from "@maruhi/core";
import { Effect, Schema } from "effect";
import { Argument, CliError as EffectCliError, Flag, Param } from "effect/cli";

import { type CommandSpec, NON_BLANK_MESSAGE } from "../cli-formatter.ts";
import { RUN_COMMAND_REQUIRED } from "../run.ts";

const nonBlank = Schema.isPattern(/\S/, { message: NON_BLANK_MESSAGE });
export const NonBlank = Schema.String.check(nonBlank);

export const NonBlankUserId = UserIdSchema.check(nonBlank);

export function singleValued(name: string, description: string) {
  return Flag.String(name).pipe(
    Flag.withDescription(description),
    Flag.withSchema(NonBlank),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  );
}

export function singleValuedAs<A>(
  name: string,
  description: string,
  schema: Schema.ConstraintCodec<A, string>,
) {
  return Flag.String(name).pipe(
    Flag.withDescription(description),
    Flag.withSchema(schema),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  );
}

export function singleFlag(name: string, description: string) {
  return Flag.Boolean(name).pipe(
    Flag.withDescription(description),
    Flag.atMost(1),
    Flag.map((values) => values[0] ?? false),
  );
}

export function specOf(config: Readonly<Record<string, Param.Any>>): CommandSpec {
  const flags: string[] = [];
  const positionals: string[] = [];
  for (const [name, param] of Object.entries(config)) {
    (param.kind === "flag" ? flags : positionals).push(name);
  }
  return { flags, positionals };
}

export const commonFlags = () => ({
  ...projectFlags(),
  env: singleValuedAs(
    "env",
    "Environment ID (default: the `defaultEnvironment` setting)",
    EnvironmentIdSchema,
  ),
});

export const projectFlags = () => ({
  server: singleValued("server", "Server URL (defaults to config server)"),
  project: singleValuedAs(
    "project",
    "Project ID (default: the `defaultProject` setting)",
    ProjectIdSchema,
  ),
});

export const serverOnlyFlags = () => ({
  server: singleValued("server", "Server URL (defaults to config server)"),
});

export const mirrorFlag = () => ({
  mirror: singleValued(
    "mirror",
    "Mirror URL to read from when the server is unreachable (default: the `mirror` setting; reads only, announced on stderr)",
  ),
});

export const runCommandArgument = () =>
  Argument.String("command").pipe(
    Argument.withDescription("The command to run, written after `--` (passed to the child as-is)"),
    Argument.atLeast(1),
    Argument.filter(
      (command) => (command[0] ?? "").trim() !== "",
      () => RUN_COMMAND_REQUIRED,
    ),
  );

export const proposalFlags = () => ({
  expires: singleValued(
    "expires",
    "How long the proposal stays approvable when the four-eyes policy turns this into a proposal (e.g. 7d, 48h; default 7d, at most 30d)",
  ),
});

export function scopeEnvFlag(description: string) {
  return Flag.String("env").pipe(
    Flag.withDescription(description),
    Flag.withSchema(EnvironmentIdSchema),
    Flag.atLeast(0),
  );
}

export function invalidFlagCombination(
  message: string,
): Effect.Effect<never, EffectCliError.ValidationError> {
  return Effect.fail(new EffectCliError.ValidationError({ message }));
}

export function rejectCombinedScopeFlags(values: {
  readonly env: readonly string[];
  readonly "all-envs": boolean;
  readonly "no-envs": boolean;
}): Effect.Effect<void, EffectCliError.ValidationError> {
  const given = [values.env.length > 0, values["all-envs"], values["no-envs"]].filter(Boolean);
  return given.length > 1
    ? invalidFlagCombination("--env, --all-envs and --no-envs cannot be combined")
    : Effect.void;
}

export function rejectNoSyncWithConfig(values: {
  readonly config: string | undefined;
  readonly "no-sync": boolean;
}): Effect.Effect<void, EffectCliError.ValidationError> {
  return values["no-sync"] && values.config !== undefined
    ? invalidFlagCombination("--no-sync and --config cannot be combined (drop one of them)")
    : Effect.void;
}
