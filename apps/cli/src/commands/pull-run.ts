import { decodeProjectId, isProjectId, type ProjectId } from "@maruhi/core";
import { Effect } from "effect";
import { Command } from "effect/cli";

import { ensurePlainRunAllowed, ensureValueDisplayAllowed } from "../agent-gate.ts";
import type { CliServices } from "../cli.ts";
import { loadCliConfig } from "../config.ts";
import type { CommonFlags, EnvironmentContext } from "../context.ts";
import { reportOwnDeviceGapFills } from "../device-gaps.ts";
import { countNoun, displayText, formatPulledLine, logWarnings, showValues } from "../display.ts";
import { CliError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { notePastDueValues } from "../max-age.ts";
import { logNote } from "../notice.ts";
import {
  ensurePlainRunOfBrokeredProjectAllowed,
  ensureProxyConfigAccepted,
  markProjectBrokered,
  DEFAULT_PROXY_CONFIG_PATH,
  type LoadedProxyConfig,
  checkProxyConfigProject,
  loadProxyConfigIfPresent,
  proxyRunOp,
} from "../proxy.package/index.ts";
import type { PulledVariables } from "../pull.ts";
import { enforceDeclaredPresence, runOp, typeAdvisoryWarnings } from "../run.ts";
import { commonFlags, mirrorFlag, runCommandArgument, singleFlag } from "./flags.ts";
import { openEnvironment, withMirrorFallback } from "./lazy.ts";
import { commandAfterTerminator, proposeCheckpointRefresh } from "./shared.ts";

export const pullConfig = {
  ...commonFlags(),
  ...mirrorFlag(),
  show: singleFlag("show", "Print the values (interactive terminals only)"),
};

export const runConfig = {
  ...commonFlags(),
  ...mirrorFlag(),
  plain: singleFlag(
    "plain",
    `Inject the real values even when ${DEFAULT_PROXY_CONFIG_PATH} is present (allowed only to a person at an interactive terminal; without the config, run always injects the real values)`,
  ),
  command: runCommandArgument(),
};

const pullForRun = Effect.fn("commands-pull-run.pullForRun")(function* (
  context: EnvironmentContext,
): Effect.fn.Return<PulledVariables, CliError, CliServices> {
  const { pullVariables } = yield* Effect.promise(() =>
    import("../pull.ts").then((m) => ({ pullVariables: m.pullVariables })),
  );

  const pulled = yield* pullVariables({
    client: context.client,
    verified: context.verified,
    environmentId: context.environmentId,
    recipient: context.recipient,
    resync: context.resync,
    floor: context.floorHandle,
  });
  yield* logWarnings(pulled.warnings);
  yield* enforceDeclaredPresence(pulled.declared);
  yield* logWarnings(typeAdvisoryWarnings(pulled.variables));
  yield* notePastDueValues({
    client: context.client,
    projectId: context.projectId,
    environmentId: context.environmentId,
    variables: pulled.variables,
  });
  return pulled;
});

export const brokeredRun = Effect.fn("commands-pull-run.brokeredRun")(function* (input: {
  readonly command: readonly string[];
  readonly flags: CommonFlags;
  readonly loaded: LoadedProxyConfig;
  readonly configPath: string;
  readonly verbose: boolean;
  readonly listen?: string | undefined;
  readonly advertise?: string | undefined;
}): Effect.fn.Return<number, CliError, CliServices> {
  const { config } = input.loaded;
  yield* checkProxyConfigProject(config, input.flags.project);
  const accepted = (projectId: ProjectId) =>
    ensureProxyConfigAccepted({
      path: input.configPath,
      content: input.loaded.content,
      projectId,
    });
  const early = input.flags.project ?? config.projectId ?? (yield* loadCliConfig).defaultProject;
  if (early !== undefined && isProjectId(early)) {
    yield* accepted(decodeProjectId(early));
  }
  const { context, pulled } = yield* withMirrorFallback(input.flags, (flags) =>
    Effect.gen(function* () {
      const opened = yield* openEnvironment({
        ...flags,
        project: flags.project ?? config.projectId,
      });
      if (opened.projectId !== early) {
        yield* accepted(opened.projectId);
      }
      yield* markProjectBrokered({ projectId: opened.projectId, configPath: input.configPath });
      return { context: opened, pulled: yield* pullForRun(opened) };
    }),
  );
  return yield* proxyRunOp({
    command: input.command,
    config,
    configPath: input.configPath,
    environmentId: context.environmentId,
    variables: pulled.variables,
    verbose: input.verbose,
    listen: input.listen,
    advertise: input.advertise,
  });
});

export function makePullRunCommands(onExitCode: (code: number) => void) {
  const pull = Command.make(
    "pull",
    pullConfig,
    Effect.fn("commands-pull-run.pull")(function* (values) {
      const io = yield* CliIo;
      if (values.show) {
        yield* ensureValueDisplayAllowed;
      }
      const { context, pulled } = yield* withMirrorFallback(values, (flags) =>
        Effect.gen(function* () {
          const { pullVariables } = yield* Effect.promise(() =>
            import("../pull.ts").then((m) => ({ pullVariables: m.pullVariables })),
          );

          const opened = yield* openEnvironment(flags);
          const read: PulledVariables = yield* pullVariables({
            client: opened.client,
            verified: opened.verified,
            environmentId: opened.environmentId,
            recipient: opened.recipient,
            resync: opened.resync,
            floor: opened.floorHandle,
            ...(flags.mirrorOf === undefined
              ? { fillOwnDeviceGaps: { signingKeyPair: opened.masterKeys.sigKeyPair } }
              : {}),
          });
          return { context: opened, pulled: read };
        }),
      );
      yield* logWarnings(pulled.warnings);
      yield* reportOwnDeviceGapFills({
        projectId: context.projectId,
        environmentId: context.environmentId,
        fills: pulled.ownDeviceGapFills,
      });
      yield* io.log(
        `Sync and verification OK: ${countNoun(pulled.variables.length, "variable")} (environment ${context.environmentId})`,
      );
      for (const variable of pulled.variables) {
        yield* io.log(formatPulledLine(variable));
      }
      for (const declared of pulled.declared) {
        yield* io.log(`${displayText(declared.name)}\t(declared — no value set)`);
      }
      yield* notePastDueValues({
        client: context.client,
        projectId: context.projectId,
        environmentId: context.environmentId,
        variables: pulled.variables,
      });
      if (values.show) {
        yield* showValues(pulled.variables);
      }
      yield* proposeCheckpointRefresh(context, { afterWrite: false });
    }),
  ).pipe(
    Command.withDescription(
      "Verify the project and environment, decrypt the values in memory, and list the variables (names, versions, and sizes; values only with --show)",
    ),
  );

  const run = Command.make(
    "run",
    runConfig,
    Effect.fn("commands-pull-run.run")(function* (values) {
      const { command: parsed, plain, ...flags } = values;
      const command = yield* commandAfterTerminator(parsed);
      const proxyConfig = yield* loadProxyConfigIfPresent(DEFAULT_PROXY_CONFIG_PATH);
      if (proxyConfig !== null && !plain) {
        onExitCode(
          yield* brokeredRun({
            command,
            flags,
            loaded: proxyConfig,
            configPath: DEFAULT_PROXY_CONFIG_PATH,
            verbose: false,
          }),
        );
        return;
      }
      if (proxyConfig !== null) {
        yield* ensurePlainRunAllowed;
        yield* logNote(
          `--plain: injecting the real values; ${DEFAULT_PROXY_CONFIG_PATH} is not applied to this run`,
        );
      } else if (plain) {
        yield* logNote(
          `--plain has no effect: no ${DEFAULT_PROXY_CONFIG_PATH} in the working directory`,
        );
      }
      const pulled = yield* withMirrorFallback(flags, (read) =>
        Effect.gen(function* () {
          const context = yield* openEnvironment(read);
          if (proxyConfig === null) {
            yield* ensurePlainRunOfBrokeredProjectAllowed(context.projectId);
          }
          return yield* pullForRun(context);
        }),
      );
      onExitCode(yield* runOp({ command, variables: pulled.variables }));
    }),
  ).pipe(
    Command.withDescription(
      `Decrypt the environment and run a command with the values injected as environment variables (memory only). When ${DEFAULT_PROXY_CONFIG_PATH} is present its brokering rules apply (as \`maruhi proxy run\`); --plain injects the real values instead, for a person at a terminal. Write the command after \`--\``,
    ),
  );

  return { pull, run };
}
