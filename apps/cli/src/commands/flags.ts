// Shared flag/argument building blocks for the command declarations (discipline: see commands/index.ts).

import { EnvironmentIdSchema, ProjectIdSchema, UserIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { Argument, Flag, Param } from "effect/cli";

import { type CommandSpec, NON_BLANK_MESSAGE } from "../cli-formatter.ts";
import { RUN_COMMAND_REQUIRED } from "../run.ts";

/* -------------------------------------------------------------------------- */
/* Declarations (checks ride on Effect's mechanisms — no hand-rolled scan) */
/* -------------------------------------------------------------------------- */

/**
 * A string that accepts no empty / whitespace-only value. Blocks the
 * accident of `maruhi push API_KEY --env "$ENV"` silently writing into the
 * default environment when ENV is unset.
 */
const nonBlank = Schema.isPattern(/\S/, { message: NON_BLANK_MESSAGE });
export const NonBlank = Schema.String.check(nonBlank);

/**
 * A non-blank internal user id. A command argument is where a typed user
 * id enters the CLI, so decoding it mints the UserId that a chain entry's
 * target requires.
 */
export const NonBlankUserId = UserIdSchema.check(nonBlank);

/**
 * One value-taking option. `atMost(1)` expresses **the refusal of a
 * duplicated flag** in the declaration (effect's default is first-wins,
 * silently). The accident shape `maruhi pull --no-show $FLAGS` that would
 * display every secret is blocked here. With `noUncheckedIndexedAccess:
 * true` the result is `string | undefined` = meshes directly with
 * context.ts's {@link CommonFlags} (no Option conversion).
 */
export function singleValued(name: string, description: string) {
  return Flag.String(name).pipe(
    Flag.withDescription(description),
    Flag.withSchema(NonBlank),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  );
}

/**
 * One value-taking option decoding through a branded-id schema — the flag
 * is where the id enters the CLI, so decoding mints the brand at the
 * declaration boundary.
 */
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

/**
 * One boolean option. **A boolean also needs `atMost(1)`**: a raw
 * `Flag.Boolean` resolves duplicates silently, and **the result changes
 * with the order typed** (measured: `--show --no-show` is `true` under
 * first-wins, `--no-show --show` is `false`). The shape where `--show`
 * sneaks into `$FLAGS` of `maruhi pull --no-show $FLAGS` (ef7cba1) must
 * not depend on the order.
 */
export function singleFlag(name: string, description: string) {
  return Flag.Boolean(name).pipe(
    Flag.withDescription(description),
    Flag.atMost(1),
    Flag.map((values) => values[0] ?? false),
  );
}

/**
 * Derive the diagnostics' command declaration from **the command
 * definition itself**. A hand-written copy would leave only the
 * diagnostics stale when a flag is added. `Param` is a public type
 * carrying `kind` (`"flag"` / `"argument"`), so they can be sorted
 * straight off the declaration listing. The name uses the object key (=
 * the spelling typed).
 */
export function specOf(config: Readonly<Record<string, Param.Any>>): CommandSpec {
  const flags: string[] = [];
  const positionals: string[] = [];
  for (const [name, param] of Object.entries(config)) {
    (param.kind === "flag" ? flags : positionals).push(name);
  }
  return { flags, positionals };
}

/* -------------------------------------------------------------------------- */
/* Command definitions                                                        */
/* -------------------------------------------------------------------------- */

/** The common flags an environment command takes (same names as context.ts's CommonFlags). */
export const commonFlags = () => ({
  ...projectFlags(),
  env: singleValuedAs(
    "env",
    "Environment ID (default: the `defaultEnvironment` setting)",
    EnvironmentIdSchema,
  ),
});

/** The common flags a project-level command takes (no env). */
export const projectFlags = () => ({
  server: singleValued("server", "Server URL (defaults to config server)"),
  project: singleValuedAs(
    "project",
    "Project ID (default: the `defaultProject` setting)",
    ProjectIdSchema,
  ),
});

/** The common flags a session-level command takes (neither project nor env). */
export const serverOnlyFlags = () => ({
  server: singleValued("server", "Server URL (defaults to config server)"),
});

/** `--mirror <url>` (PF2 — AUTH_SPEC §11-7): the read-only replica a read falls back to when the server is unreachable. */
export const mirrorFlag = () => ({
  mirror: singleValued(
    "mirror",
    "Mirror URL to read from when the server is unreachable (default: the `mirror` setting; reads only, announced on stderr)",
  ),
});

/** The declaration of the run target (after `--`) shared by `run` / `ci run`. */
export const runCommandArgument = () =>
  // Everything after `--` lands here (empty strings are kept too).
  // `atLeast(1)` drops "a run with no run target" and `filter` drops "a
  // run target that is an empty string" (the unset shape of `maruhi run --
  // "$CMD"`). Both are declarations, and a second-or-later empty string is
  // **kept as a child-process argument**. On rc.117 an atLeast of 0 becomes
  // `MissingArgument`. The wording mapping lives in cli-formatter.ts (only
  // the command argument is RUN_COMMAND_REQUIRED)
  Argument.String("command").pipe(
    Argument.withDescription("The command to run, written after `--` (passed to the child as-is)"),
    Argument.atLeast(1),
    Argument.filter(
      (command) => (command[0] ?? "").trim() !== "",
      () => RUN_COMMAND_REQUIRED,
    ),
  );

/**
 * The expiry flag taken by commands that can become proposals under
 * four-eyes (CRYPTO_SPEC §6.2 — K6). Never read on an operation the
 * policy doesn't target (a direct append).
 */
export const proposalFlags = () => ({
  expires: singleValued(
    "expires",
    "How long the proposal stays approvable when the four-eyes policy turns this into a proposal (e.g. 7d, 48h; default 7d, at most 30d)",
  ),
});

/** `--env <id>` (repeatable) — the scope of invite / change-role (CRYPTO_SPEC §6.2 — 2026-09-15 ES K4). */
export function scopeEnvFlag(description: string) {
  return Flag.String("env").pipe(
    Flag.withDescription(description),
    Flag.withSchema(EnvironmentIdSchema),
    // Express repetition in the declaration (0 or more — atLeast(0) gives readonly EnvironmentId[])
    Flag.atLeast(0),
  );
}
