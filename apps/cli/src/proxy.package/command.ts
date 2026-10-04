// `maruhi proxy` (discipline: see commands/index.ts).

import { isProjectId } from "@maruhi/core";
import { Effect } from "effect";
import { Command } from "effect/cli";

import { commonFlags, runCommandArgument, singleFlag, singleValued } from "../commands/flags.ts";
import { brokeredRun } from "../commands/pull-run.ts";
import { commandAfterTerminator } from "../commands/shared.ts";
import { ConfigStore } from "../config.ts";
import { usageError } from "../errors.ts";
import { logNote } from "../notice.ts";
import { acceptProxyConfig } from "./proxy-accept.ts";
import {
  DEFAULT_PROXY_CONFIG_PATH,
  checkProxyConfigProject,
  loadProxyConfig,
} from "./proxy-config.ts";
import { describeProxyConfig } from "./proxy-run.ts";

/**
 * `maruhi proxy run -- <command>` (PF4 — credential brokering): `run`'s
 * flags plus the proxy config path and a per-request log switch. The run
 * target is declared exactly like `run`'s.

 * @public
 */
export const proxyRunConfig = {
  ...commonFlags(),
  config: singleValued(
    "config",
    `Path to the proxy config committed in the repository (default: ${DEFAULT_PROXY_CONFIG_PATH})`,
  ),
  verbose: singleFlag(
    "verbose",
    "Print one line per request the proxy handles (method, host, path, and the variables substituted — never a value)",
  ),
  listen: singleValued(
    "listen",
    "Bind the proxy to host[:port] instead of the loopback, so a sandbox or container can reach it (every request still needs the run's proxy credential)",
  ),
  advertise: singleValued(
    "advertise",
    "The host[:port] the command is told to use for the proxy when it differs from the bound address (for example host.docker.internal from a container)",
  ),
  command: runCommandArgument(),
};
/** @public */
export const proxyAcceptConfig = {
  config: singleValued(
    "config",
    `Path to the proxy config to accept (default: ${DEFAULT_PROXY_CONFIG_PATH})`,
  ),
  project: singleValued(
    "project",
    "The project the config is for (default: the config's `project`, else the default project)",
  ),
};
/** @public */
export function makeProxyCommands(onExitCode: (code: number) => void) {
  // `maruhi proxy run` (PF4 — pf4-design.md). The same prologue as run
  // (config → environment → verified pull → presence fail-fast → type
  // advisory); what differs is what the child receives (proxy-run.ts)
  const proxyRun = Command.make("run", proxyRunConfig, (values) =>
    Effect.gen(function* () {
      const { command: parsed, config: configFlag, verbose, listen, advertise, ...flags } = values;
      // Drops before communication / decryption (at the command body's head)
      const command = yield* commandAfterTerminator(parsed);
      // The config is read before any network (a broken file is reported first)
      const configPath = configFlag ?? DEFAULT_PROXY_CONFIG_PATH;
      const proxyConfig = yield* loadProxyConfig(configPath);
      onExitCode(
        yield* brokeredRun({
          command,
          flags,
          loaded: proxyConfig,
          configPath,
          verbose,
          listen,
          advertise,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Run a command behind a local credential-brokering proxy: brokered variables arrive as placeholders and the real values are substituted only in requests to the hosts the proxy config allows. Write the command after `--`",
    ),
  );

  // `maruhi proxy accept` (pf4-design.md §21 R-8 / R-14): a person at a
  // terminal records the config's content as accepted on this machine —
  // the explicit act the brokering rules need before they apply (the
  // direnv model). Reads the file, contacts no server
  const proxyAccept = Command.make("accept", proxyAcceptConfig, (values) =>
    Effect.gen(function* () {
      const configPath = values.config ?? DEFAULT_PROXY_CONFIG_PATH;
      const loaded = yield* loadProxyConfig(configPath);
      // The project the rules are for: the flag, the config's `project`, or
      // the default project — resolved without any network (the mark it
      // arms is per project, R-18)
      yield* checkProxyConfigProject(loaded.config, values.project);
      const projectId =
        values.project ??
        loaded.config.projectId ??
        (yield* (yield* ConfigStore).load).defaultProject;
      if (projectId === undefined) {
        return yield* Effect.fail(
          usageError(
            "Cannot tell which project the proxy config is for: pass --project <id>, set `project` in the config, or set a default project (`maruhi config set defaultProject <id>`)",
          ),
        );
      }
      if (!isProjectId(projectId)) {
        return yield* Effect.fail(usageError("Invalid project ID (64 hex digits)"));
      }
      const outcome = yield* acceptProxyConfig({
        path: configPath,
        content: loaded.content,
        projectId,
      });
      yield* logNote(
        outcome === "unchanged"
          ? `${configPath} is already accepted on this machine with this content for this project; nothing changed`
          : `${configPath} accepted on this machine for project ${projectId} (${outcome === "changed" ? "replaces the content accepted before" : outcome === "project added" ? "the same content was already accepted for another project" : "first use"}): ${describeProxyConfig(loaded.config)}. A change to the file will need \`maruhi proxy accept\` again`,
      );
    }),
  ).pipe(
    Command.withDescription(
      "Accept the proxy config on this machine so its rules apply to `maruhi run` and `maruhi proxy run` (a person at a terminal; a new or changed file is refused until accepted). Reads the file and contacts no server",
    ),
  );

  const proxy = Command.make("proxy").pipe(
    Command.withDescription(
      "Credential brokering for AI agents and other programs: run a command that never holds the real values (run), after a person accepted the repository's proxy config on this machine (accept)",
    ),
    Command.withSubcommands([proxyRun, proxyAccept]),
  );

  return proxy;
}
