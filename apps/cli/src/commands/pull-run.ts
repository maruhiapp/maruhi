// `maruhi pull` / `maruhi run` (discipline: see commands/index.ts).

import { Effect } from "effect";
import { Command } from "effect/cli";

import { ensurePlainRunAllowed, ensureValueDisplayAllowed } from "../agent-gate.ts";
import { ConfigStore } from "../config.ts";
import {
  type CliServices,
  type CommonFlags,
  type EnvironmentContext,
  openEnvironment,
  withMirrorFallback,
} from "../context.ts";
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
} from "../proxy-accept.ts";
import {
  DEFAULT_PROXY_CONFIG_PATH,
  type LoadedProxyConfig,
  checkProxyConfigProject,
  loadProxyConfigIfPresent,
} from "../proxy-config.ts";
import { proxyRunOp } from "../proxy-run.ts";
import { type PulledVariables, pullVariables } from "../pull.ts";
import { enforceDeclaredPresence, runOp, typeAdvisoryWarnings } from "../run.ts";
import { commonFlags, mirrorFlag, runCommandArgument, singleFlag } from "./flags.ts";
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

/**
 * The verified pull every run shape shares: decrypt the environment, show
 * the pull's warnings, the presence fail-fast (design doc §1-4 — rulings CT /
 * CU: a required = true declared in the verified set fails with a typed
 * error before any child starts), the advisory type check (§14.3-7 — a
 * mismatch warns only).
 */
function pullForRun(
  context: EnvironmentContext,
): Effect.Effect<PulledVariables, CliError, CliServices> {
  return Effect.gen(function* () {
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
    // The point-of-use nudge (PF7a): one note when a value just pulled is
    // past the max age its schema declares (never changes the outcome)
    yield* notePastDueValues({
      client: context.client,
      projectId: context.projectId,
      environmentId: context.environmentId,
      variables: pulled.variables,
    });
    return pulled;
  });
}

/**
 * The brokered run shared by `maruhi proxy run` and by `maruhi run` when
 * the repository has a proxy config: project check → environment →
 * verified pull → presence fail-fast → type advisory → proxy-run.ts.
 */
export function brokeredRun(input: {
  readonly command: readonly string[];
  readonly flags: CommonFlags;
  readonly loaded: LoadedProxyConfig;
  readonly configPath: string;
  readonly verbose: boolean;
  readonly listen?: string | undefined;
  readonly advertise?: string | undefined;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const { config } = input.loaded;
    yield* checkProxyConfigProject(config, input.flags.project);
    // A config is applied only once a person accepted its content on this
    // machine **for this project** (pf4-design.md §21 R-8 / R-24 — an agent
    // cannot accept its own rules, nor point another project's accepted
    // rules at this one). Checked before any network when the project is
    // known without it, and again against the project the prologue resolved
    const accepted = (projectId: string) =>
      ensureProxyConfigAccepted({
        path: input.configPath,
        content: input.loaded.content,
        projectId,
      });
    const early =
      input.flags.project ?? config.projectId ?? (yield* (yield* ConfigStore).load).defaultProject;
    if (early !== undefined) {
      yield* accepted(early);
    }
    // The read may be retried against the configured mirror (PF2); the proxy then starts once
    const { context, pulled } = yield* withMirrorFallback(input.flags, (flags) =>
      Effect.gen(function* () {
        const opened = yield* openEnvironment({
          ...flags,
          project: flags.project ?? config.projectId,
        });
        if (opened.projectId !== early) {
          yield* accepted(opened.projectId);
        }
        // From now on plain `run` without a config is gated for this project (R-13)
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
}

export function makePullRunCommands(onExitCode: (code: number) => void) {
  const pull = Command.make("pull", pullConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // The value-display refusal is the command entry = checked **before
      // decryption** (never decrypt the whole environment first and then
      // refuse = never build decrypted plaintext at all). The same check
      // also exists in the post-decryption showValues — that one is a
      // defense line (display.ts)
      if (values.show) {
        yield* ensureValueDisplayAllowed;
      }
      // The read (the prologue and the pull) may be retried against the
      // configured mirror when the server is unreachable (PF2)
      const { context, pulled } = yield* withMirrorFallback(values, (flags) =>
        Effect.gen(function* () {
          const opened = yield* openEnvironment(flags);
          const read: PulledVariables = yield* pullVariables({
            client: opened.client,
            verified: opened.verified,
            environmentId: opened.environmentId,
            recipient: opened.recipient,
            resync: opened.resync,
            floor: opened.floorHandle,
            // Filling the missing epochs of my other devices (DK K11-4 — pull
            // only; a registration the mirror would refuse, so not on the
            // fallback read)
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
      // declared (valueless declarations — §4.2 layout v2) are listed as
      // metadata rows (no value or version exists. The schema's detail is
      // `maruhi schema`)
      for (const declared of pulled.declared) {
        yield* io.log(`${displayText(declared.name)}\t(declared — no value set)`);
      }
      // The point-of-use nudge (PF7a): values past their declared max age
      yield* notePastDueValues({
        client: context.client,
        projectId: context.projectId,
        environmentId: context.environmentId,
        variables: pulled.variables,
      });
      if (values.show) {
        yield* showValues(pulled.variables);
      }
      // Issuance trigger (iii) (CRYPTO_SPEC §6.3): detecting the baseline
      // checkpoint's staleness on a successful pull. Proposal only (never
      // auto-issued)
      yield* proposeCheckpointRefresh(context, { includeAnchor: false });
    }),
  ).pipe(
    Command.withDescription(
      "Verify the project and environment, decrypt the values in memory, and list the variables (names, versions, and sizes; values only with --show)",
    ),
  );

  const run = Command.make("run", runConfig, (values) =>
    Effect.gen(function* () {
      const { command: parsed, plain, ...flags } = values;
      // Drops before communication / decryption (at the command body's head)
      const command = yield* commandAfterTerminator(parsed);
      // The repository's proxy config, when present, decides what the child
      // receives (ADR-0016 decision 7 revision 2 — pf4-design.md §20): the
      // same brokering as `proxy run`. `--plain` keeps the real-value shape,
      // only for a person at a terminal. Read before any network
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
      // The read may be retried against the configured mirror when the
      // server is unreachable (PF2); the command then runs once
      const pulled = yield* withMirrorFallback(flags, (read) =>
        Effect.gen(function* () {
          const context = yield* openEnvironment(read);
          if (proxyConfig === null) {
            // A project brokered on this machine: the real values only to a
            // person at a terminal (deleting the config or changing directory
            // is not a way around the rules — pf4-design.md §21 R-13)
            yield* ensurePlainRunOfBrokeredProjectAllowed(context.projectId);
          }
          return yield* pullForRun(context);
        }),
      );
      // Environment-variable names go through verified statements (§4.2 /
      // §12-7). The execution-control variable-name denylist (run.ts) is a
      // defense layer applied to the verified name
      onExitCode(yield* runOp({ command, variables: pulled.variables }));
    }),
  ).pipe(
    Command.withDescription(
      `Decrypt the environment and run a command with the values injected as environment variables (memory only). When ${DEFAULT_PROXY_CONFIG_PATH} is present its brokering rules apply (as \`maruhi proxy run\`); --plain injects the real values instead, for a person at a terminal. Write the command after \`--\``,
    ),
  );

  return { pull, run };
}
