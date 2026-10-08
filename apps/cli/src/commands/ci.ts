// `maruhi ci` (discipline: see commands/index.ts).

import { isEnvironmentId, isProjectId, type EnvironmentId, type ProjectId } from "@maruhi/core";
import { Effect } from "effect";
import { Argument, Command, Flag } from "effect/cli";

import { MAX_PROPOSAL_DAYS, ciRotateOp, describeProposal } from "../ci-rotate.ts";
import { ciRunOp } from "../ci-run.ts";
import { type CliServices } from "../context.ts";
import { displayText } from "../display.ts";
import { CliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import {
  DEFAULT_ROTATE_CONFIG_PATH,
  loadRotateConfig,
  configNamesProject as rotateConfigNamesProject,
} from "../rotate-config.ts";
import { normalizeHttpOrigin } from "../session.ts";
import {
  ciSyncOp,
  DEFAULT_SYNC_CONFIG_PATH,
  checkConfigProject,
  loadSyncConfig,
  requireSyncTarget,
} from "../sync.package/index.ts";
import { logRotationWarnings } from "../var-rotate.ts";
import { NonBlank, runCommandArgument, singleFlag, singleValued } from "./flags.ts";
import { ENV_FLAG_SHAPE_MESSAGE, commandAfterTerminator } from "./shared.ts";

/**
 * `maruhi ci run`'s declaration: unlike an ordinary run it reads no
 * config file, so server / project / env are **mandatory as flags**. On
 * the declaration they are optional (singleValued), and a missing one is
 * diagnosed by the body side with the CI-specific fix ("write the flag",
 * not "set it in config").
 */
export const ciRunConfig = {
  server: singleValued("server", "Server URL (required; CI mode reads no config file)"),
  project: singleValued("project", "Project ID, which is the pinned genesis hash (required)"),
  env: singleValued("env", "Environment ID to lease (required)"),
  audience: singleValued("audience", "OIDC audience to request (default: the server origin)"),
  mirror: singleValued(
    "mirror",
    "Mirror URL to lease from when the server is unreachable (a second OIDC token is requested for the mirror's audience unless --audience is given)",
  ),
  anchor: singleValued(
    "anchor",
    "Path to the committed repository anchor file (generate it with `maruhi project anchor`)",
  ),
  command: runCommandArgument(),
};

/**
 * `maruhi ci sync <target>`'s declaration (SY2 stage 2 — ruling D): like
 * `ci run` it reads no config file (server / project are mandatory flags).
 * There is no `--env` since the sync config's target decides the
 * environment. `--yes` is the same word as the local apply.
 */
export const ciSyncConfig = {
  server: singleValued("server", "Server URL (required; CI mode reads no config file)"),
  project: singleValued("project", "Project ID, which is the pinned genesis hash (required)"),
  audience: singleValued("audience", "OIDC audience to request (default: the server origin)"),
  mirror: singleValued(
    "mirror",
    "Mirror URL to lease from when the server is unreachable (a second OIDC token is requested for the mirror's audience unless --audience is given)",
  ),
  anchor: singleValued(
    "anchor",
    "Path to the committed repository anchor file (generate it with `maruhi project anchor`)",
  ),
  config: singleValued(
    "config",
    `Path to the sync config committed in the repository (default: ${DEFAULT_SYNC_CONFIG_PATH})`,
  ),
  yes: singleFlag(
    "yes",
    "Write to a production target (without it, a production target only shows the plan)",
  ),
  target: Argument.String("target").pipe(
    Argument.withDescription("Target name from the sync config (a key under `targets`)"),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi ci rotate <NAME>` (a sealed value proposal from a CI job — PF7b). */
export const ciRotateConfig = {
  server: singleValued("server", "Server URL (required; CI mode reads no config file)"),
  project: singleValued("project", "Project ID, which is the pinned genesis hash (required)"),
  env: singleValued("env", "Environment ID of the variable to rotate (required)"),
  audience: singleValued("audience", "OIDC audience to request (default: the server origin)"),
  anchor: singleValued(
    "anchor",
    "Path to the committed repository anchor file (generate it with `maruhi project anchor`)",
  ),
  "rotate-config": singleValued(
    "rotate-config",
    `Path to the rotation config naming the connector and admin credential of each variable (default: ${DEFAULT_ROTATE_CONFIG_PATH} in the working directory)`,
  ),
  "expires-in": Flag.Int("expires-in").pipe(
    Flag.withDescription(
      `Days the proposal waits for a member before it expires (1 to ${MAX_PROPOSAL_DAYS}; default 7)`,
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription(
      "Variable name to rotate (the rule's variable, or the access key id an AWS rule pairs with it)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/**
 * Resolving `maruhi ci run`'s required flags: never falls back to the
 * config file (a CI runner has no persistent config, and pinning the
 * genesis belongs to the workflow YAML's review). The diagnostic also
 * says "write the flag", not "set it in config".
 */
function requireCiFlag(
  value: string | undefined,
  flag: string,
  command: "ci run" | "ci sync" | "ci rotate" = "ci run",
): Effect.Effect<string, CliError> {
  if (value !== undefined) {
    return Effect.succeed(value);
  }
  // `ci sync` has no `--env` (the sync config's target decides the
  // environment), so the fix is stated per command
  const guidance = {
    "ci run": `ci run requires ${flag} (CI mode reads no config file — pass --server, --project, and --env explicitly in the workflow)`,
    "ci sync": `ci sync requires ${flag} (CI mode reads no config file except the sync config — pass --server and --project explicitly in the workflow; the environment comes from the target)`,
    "ci rotate": `ci rotate requires ${flag} (CI mode reads no config file except the rotation config — pass --server, --project, and --env explicitly in the workflow)`,
  };
  return Effect.fail(usageError(guidance[command]));
}

/** The lease target of a CI read: the server, or the mirror on the retry. */
interface CiTarget {
  readonly origin: string;
  readonly audience: string;
}

/**
 * The CI read's fallback (PF2 — AUTH_SPEC §11-7 ruling E): when the server
 * is unreachable and `--mirror` names a replica, the lease is requested
 * there instead, with an OIDC token for the mirror's audience unless
 * --audience was given (the mirror's own grant names its audience). Never
 * on an answer of the server (a 404 or a 401 is not retried)
 */
const withCiMirrorFallback = Effect.fn("commands-ci.withCiMirrorFallback")(function* <A>(
  values: { readonly mirror?: string | undefined; readonly audience?: string | undefined },
  primary: CiTarget,
  attempt: (target: CiTarget) => Effect.Effect<A, CliError, CliServices>,
): Effect.fn.Return<A, CliError, CliServices> {
  if (values.mirror === undefined) {
    return yield* attempt(primary);
  }
  const mirror = yield* normalizeHttpOrigin(values.mirror, "the mirror URL");
  if (mirror === primary.origin) {
    return yield* Effect.fail(
      usageError("--mirror is the server URL itself (pass the mirror deployment's URL)"),
    );
  }
  return yield* attempt(primary).pipe(
    Effect.catch((error: CliError) =>
      error.unreachable === true
        ? Effect.gen(function* () {
            const io = yield* CliIo;
            yield* io.logError(
              `${error.message}. Retrying against the mirror ${mirror} (a read-only replica that may be behind the server)`,
            );
            return yield* attempt({ origin: mirror, audience: values.audience ?? mirror });
          })
        : Effect.fail(error),
    ),
  );
});

/** `maruhi ci run -- <cmd>`'s body (verification lives in ci-run.ts / lease-client.ts). */
const ciRunCommand = Effect.fn("commands-ci.ciRunCommand")(function* (values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
  readonly audience?: string | undefined;
  readonly mirror?: string | undefined;
  readonly anchor?: string | undefined;
  readonly command: readonly string[];
}): Effect.fn.Return<number, CliError, CliServices> {
  // Every format check precedes network / key generation (the same discipline as the existing commands)
  const origin = yield* normalizeHttpOrigin(
    yield* requireCiFlag(values.server, "--server"),
    "the server URL",
  );
  const projectFlag = yield* requireCiFlag(values.project, "--project");
  if (!isProjectId(projectFlag)) {
    return yield* Effect.fail(
      usageError("Invalid project ID for --project (the genesis hash — 64 hex digits)"),
    );
  }
  const envFlag = yield* requireCiFlag(values.env, "--env");
  if (!isEnvironmentId(envFlag)) {
    return yield* Effect.fail(usageError(ENV_FLAG_SHAPE_MESSAGE));
  }
  // audience's default is the server's normalized origin (AUTH_SPEC §14-1's recommended value)
  return yield* withCiMirrorFallback(
    values,
    { origin, audience: values.audience ?? origin },
    (target) =>
      ciRunOp({
        origin: target.origin,
        projectId: projectFlag,
        environmentId: envFlag,
        audience: target.audience,
        anchorPath: values.anchor,
        command: values.command,
      }),
  );
});

/** `maruhi ci sync <target>`'s body (the lease and the sync live in sync-ci.ts). */
const ciSyncCommand = Effect.fn("commands-ci.ciSyncCommand")(function* (values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly audience?: string | undefined;
  readonly mirror?: string | undefined;
  readonly anchor?: string | undefined;
  readonly config?: string | undefined;
  readonly yes: boolean;
  readonly target: string;
}): Effect.fn.Return<void, CliError, CliServices> {
  // The format checks and the config read precede network / key
  // generation (the same discipline as ci run). There is no `--env`: the
  // sync config's target decides the environment
  const origin = yield* normalizeHttpOrigin(
    yield* requireCiFlag(values.server, "--server", "ci sync"),
    "the server URL",
  );
  const projectFlag = yield* requireCiFlag(values.project, "--project", "ci sync");
  if (!isProjectId(projectFlag)) {
    return yield* Effect.fail(
      usageError("Invalid project ID for --project (the genesis hash — 64 hex digits)"),
    );
  }
  const config = yield* loadSyncConfig(values.config ?? DEFAULT_SYNC_CONFIG_PATH);
  const target = yield* requireSyncTarget(config, values.target);
  yield* checkConfigProject(config, projectFlag);
  yield* withCiMirrorFallback(values, { origin, audience: values.audience ?? origin }, (where) =>
    ciSyncOp({
      origin: where.origin,
      projectId: projectFlag,
      audience: where.audience,
      anchorPath: values.anchor,
      target,
      yes: values.yes,
    }),
  );
});

/** `maruhi ci rotate <NAME>`'s body (the lease, the connector, and the sealed proposal live in ci-rotate.ts). */
/** The coordinates of `maruhi ci rotate` (every format check before the config read and the network). */
const ciRotateCoordinates = Effect.fn("commands-ci.ciRotateCoordinates")(function* (values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
  readonly "expires-in"?: number | undefined;
}): Effect.fn.Return<
  {
    readonly origin: string;
    readonly projectId: ProjectId;
    readonly environmentId: EnvironmentId;
    readonly expiresInDays: number;
  },
  CliError
> {
  const origin = yield* normalizeHttpOrigin(
    yield* requireCiFlag(values.server, "--server", "ci rotate"),
    "the server URL",
  );
  const projectId = yield* requireCiFlag(values.project, "--project", "ci rotate");
  if (!isProjectId(projectId)) {
    return yield* Effect.fail(
      usageError("Invalid project ID for --project (the genesis hash — 64 hex digits)"),
    );
  }
  const environmentId = yield* requireCiFlag(values.env, "--env", "ci rotate");
  if (!isEnvironmentId(environmentId)) {
    return yield* Effect.fail(usageError(ENV_FLAG_SHAPE_MESSAGE));
  }
  const expiresInDays = values["expires-in"] ?? 7;
  if (!Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > MAX_PROPOSAL_DAYS) {
    return yield* Effect.fail(
      usageError(`--expires-in must be a number of days from 1 to ${MAX_PROPOSAL_DAYS}`),
    );
  }
  return { origin, projectId, environmentId, expiresInDays };
});

/** `maruhi ci rotate <NAME>`'s body (the lease, the connector, and the sealed proposal live in ci-rotate.ts). */
const ciRotateCommand = Effect.fn("commands-ci.ciRotateCommand")(function* (values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
  readonly audience?: string | undefined;
  readonly anchor?: string | undefined;
  readonly "rotate-config"?: string | undefined;
  readonly "expires-in"?: number | undefined;
  readonly name: string;
}): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const coordinates = yield* ciRotateCoordinates(values);
  // The config is read before any network / key generation (the same
  // discipline as ci run)
  const rotateConfigPath = values["rotate-config"] ?? DEFAULT_ROTATE_CONFIG_PATH;
  const rotateConfig = yield* loadRotateConfig(rotateConfigPath);
  if (!rotateConfigNamesProject(rotateConfig, coordinates.projectId)) {
    return yield* Effect.fail(
      usageError(
        `The rotation config ${displayText(rotateConfigPath)} belongs to a different project (its \`project\` does not match --project)`,
      ),
    );
  }
  const result = yield* ciRotateOp({
    ...coordinates,
    audience: values.audience ?? coordinates.origin,
    anchorPath: values.anchor,
    name: values.name,
    config: rotateConfig,
    configPath: rotateConfigPath,
  });
  yield* logRotationWarnings(result.warnings);
  for (const line of describeProposal(result, coordinates.environmentId)) {
    yield* io.log(line);
  }
});

export function makeCiCommands(onExitCode: (code: number) => void) {
  const ciRun = Command.make(
    "run",
    ciRunConfig,
    Effect.fn("commands-ci.ciRun")(function* (values) {
      const { command: parsed, ...flags } = values;
      // Drops before communication / key generation (at the command body's head) (the same `--` discipline as run)
      const command = yield* commandAfterTerminator(parsed);
      onExitCode(yield* ciRunCommand({ ...flags, command }));
    }),
  ).pipe(
    Command.withDescription(
      "Lease the environment via OIDC (no sign-in, no keychain), verify it, and run a command with the values injected. Write the command after `--`",
    ),
  );

  const ciSync = Command.make("sync", ciSyncConfig, (values) => ciSyncCommand(values)).pipe(
    Command.withDescription(
      "Lease the target's environment via OIDC (no sign-in, no keychain) and write every selected variable to the deploy target through its driver. Keeps no receipt and deletes nothing; a production target needs --yes",
    ),
  );

  const ciRotate = Command.make("rotate", ciRotateConfig, (values) => ciRotateCommand(values)).pipe(
    Command.withDescription(
      "Lease the environment via OIDC, create a new credential at the issuer through the rule's connector, and store it as a sealed proposal for a member to accept (no signing key in CI). Never displays a value",
    ),
  );

  const ci = Command.make("ci").pipe(
    Command.withDescription("Commands for CI jobs (run / sync / rotate)"),
    Command.withSubcommands([ciRun, ciSync, ciRotate]),
  );

  return ci;
}
