import { join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { type ProjectId, ProjectIdSchema } from "@maruhi/core";
import { Clock, Context, Effect, FileSystem, Schema, Stdio } from "effect";

import { AgentProfileRef, describeNonTerminal, ensureHumanCeremonyAllowed } from "../agent-gate.ts";
import { cliError, type CliError } from "../errors.ts";
import type { CliIo } from "../io.ts";
import { type LedgerRead, readJsonFile, writeJsonFileAtomic } from "../json-record.ts";
import { logNote } from "../notice.ts";

export interface AcceptedProxyConfig {
  readonly content: string;
  readonly acceptedAtMs: number;
  readonly projectIds: readonly ProjectId[];
}

export interface BrokeredProject {
  readonly configPath: string;
  readonly markedAtMs: number;
}

export type AcceptedLookup =
  | { readonly state: "found"; readonly accepted: AcceptedProxyConfig }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

export type BrokeredLookup =
  | { readonly state: "found"; readonly mark: BrokeredProject }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

export interface ProxyAcceptStoreShape {
  readonly filePath: string;
  readonly lookup: (configPath: string) => Effect.Effect<AcceptedLookup, CliError>;
  readonly accept: (
    configPath: string,
    accepted: AcceptedProxyConfig,
  ) => Effect.Effect<void, CliError>;
  readonly brokeredProject: (projectId: ProjectId) => Effect.Effect<BrokeredLookup, CliError>;
  readonly markBrokered: (
    projectId: ProjectId,
    mark: BrokeredProject,
  ) => Effect.Effect<void, CliError>;
}

export class ProxyAcceptStore extends Context.Service<ProxyAcceptStore, ProxyAcceptStoreShape>()(
  "cli/ProxyAcceptStore",
) {}

export function acceptedProxyConfigsPathOf(home: string): string {
  return join(home, ".config", "maruhi", "proxy-accepted.json");
}

const LEDGER = Schema.Struct({
  v: Schema.Literal(1),
  accepted: Schema.Record(
    Schema.String,
    Schema.Struct({
      content: Schema.String,
      acceptedAtMs: Schema.Int,
      projectIds: Schema.Array(ProjectIdSchema),
    }),
  ),
  projects: Schema.Record(
    Schema.String,
    Schema.Struct({
      configPath: Schema.String,
      markedAtMs: Schema.Int,
    }),
  ),
});

type AcceptedFile = (typeof LEDGER)["Type"];

const EMPTY_FILE: AcceptedFile = { v: 1, accepted: {}, projects: {} };

export function makeFileProxyAcceptStore(path: string): ProxyAcceptStoreShape {
  const loadRaw = (): Effect.Effect<LedgerRead<AcceptedFile>> =>
    readJsonFile(path, LEDGER).pipe(
      Effect.catchTag("PlatformError", () =>
        Effect.succeed<LedgerRead<AcceptedFile>>({ state: "corrupt" }),
      ),
      Effect.provide(BunFileSystem.layer),
    );

  const cannotRecord = (what: string): CliError =>
    cliError(
      `Cannot record ${what} (the record is corrupt, unreadable, or cannot be written): ${path} — inspect it, and if the modification was unintended, delete it and re-run`,
    );

  const merge = (apply: (file: AcceptedFile) => AcceptedFile, what: string) =>
    Effect.gen(function* () {
      const loaded = yield* loadRaw();
      if (loaded.state === "corrupt") {
        return yield* Effect.fail(cannotRecord(what));
      }
      const file = apply(loaded.state === "missing" ? EMPTY_FILE : loaded.file);
      yield* writeJsonFileAtomic(path, LEDGER, file).pipe(
        Effect.mapError(() => cannotRecord(what)),
        Effect.provide(BunFileSystem.layer),
      );
    });

  return {
    filePath: path,
    lookup: Effect.fn("proxy-accept.lookup")(function* (configPath) {
      const loaded = yield* loadRaw();
      if (loaded.state !== "loaded") {
        return loaded;
      }
      const accepted = Object.hasOwn(loaded.file.accepted, configPath)
        ? loaded.file.accepted[configPath]
        : undefined;
      return accepted === undefined
        ? { state: "missing" }
        : {
            state: "found",
            accepted,
          };
    }),
    accept: (configPath, accepted) =>
      merge(
        (file) => ({ ...file, accepted: { ...file.accepted, [configPath]: accepted } }),
        "the accepted proxy config",
      ),
    brokeredProject: Effect.fn("proxy-accept.brokeredProject")(function* (projectId) {
      const loaded = yield* loadRaw();
      if (loaded.state !== "loaded") {
        return loaded;
      }
      const mark = Object.hasOwn(loaded.file.projects, projectId)
        ? loaded.file.projects[projectId]
        : undefined;
      return mark === undefined ? { state: "missing" } : { state: "found", mark };
    }),
    markBrokered: (projectId, mark) =>
      merge(
        (file) =>
          Object.hasOwn(file.projects, projectId)
            ? file
            : { ...file, projects: { ...file.projects, [projectId]: mark } },
        "the brokered project",
      ),
  };
}

const ACCEPT_COMMAND = "`maruhi proxy accept`";

function resolvedPath(path: string): Effect.Effect<string, CliError> {
  return FileSystem.FileSystem.pipe(Effect.flatMap((fs) => fs.realPath(path))).pipe(
    Effect.mapError(() => cliError(`Cannot resolve the path of the proxy config ${path}`)),
    Effect.provide(BunFileSystem.layer),
  );
}

function corruptRecord(filePath: string): CliError {
  return cliError(
    `The record of accepted proxy configs cannot be read (corrupt or unreadable): ${filePath} — inspect it, and if the modification was unintended, delete it and run ${ACCEPT_COMMAND} again from a terminal`,
  );
}

const howToAccept = Effect.fn("proxy-accept.howToAccept")(function* (): Effect.fn.Return<
  string,
  never,
  Stdio.Stdio
> {
  const agent = yield* AgentProfileRef;
  if (agent.isAgent) {
    const detected = agent.name === undefined ? "" : ` (${agent.name})`;
    return `an AI agent environment was detected${detected}: a person reviews the file and runs ${ACCEPT_COMMAND} from a terminal (an agent cannot accept its own rules); until then the values are neither brokered nor injected`;
  }
  const stdio = yield* Stdio.Stdio;
  const stdinIsTerminal = yield* stdio.stdinIsTerminal;
  const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
  if (!stdinIsTerminal || !stdoutIsTerminal) {
    return `${describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal })}: review the file and run ${ACCEPT_COMMAND} from a terminal (pipes, redirects, CI, and AI agents cannot accept it)`;
  }
  return `review it, then run ${ACCEPT_COMMAND} to accept it`;
});

export const ensureProxyConfigAccepted = Effect.fn("proxy-accept.ensureProxyConfigAccepted")(
  function* (input: {
    readonly path: string;
    readonly content: string;
    readonly projectId: ProjectId;
  }): Effect.fn.Return<void, CliError, ProxyAcceptStore | Stdio.Stdio> {
    const store = yield* ProxyAcceptStore;
    const lookup = yield* store.lookup(yield* resolvedPath(input.path));
    if (lookup.state === "corrupt") {
      return yield* Effect.fail(corruptRecord(store.filePath));
    }
    if (lookup.state === "found" && lookup.accepted.content === input.content) {
      if (lookup.accepted.projectIds.includes(input.projectId)) {
        return;
      }
      return yield* Effect.fail(
        cliError(
          `Refused to apply the proxy config ${input.path}: it is accepted on this machine for a different project, not for this one; a person reviews it and runs ${ACCEPT_COMMAND} with --project for this project`,
        ),
      );
    }
    const change =
      lookup.state === "missing"
        ? "it has not been accepted on this machine yet"
        : "it has changed since it was accepted on this machine";
    return yield* Effect.fail(
      cliError(
        `Refused to apply the proxy config ${input.path}: ${change}, and ${yield* howToAccept()}`,
      ),
    );
  },
);

export const acceptProxyConfig = Effect.fn("proxy-accept.acceptProxyConfig")(function* (input: {
  readonly path: string;
  readonly content: string;
  readonly projectId: ProjectId;
}): Effect.fn.Return<
  "first use" | "changed" | "project added" | "unchanged",
  CliError,
  ProxyAcceptStore | Stdio.Stdio
> {
  yield* ensureHumanCeremonyAllowed({
    agentRefusal: (detected) =>
      `Refused to accept the proxy config: an AI agent environment was detected${detected}. Accepting the rules is a person's act (an agent cannot accept its own rules): run ${ACCEPT_COMMAND} yourself from a terminal`,
    terminalRefusal: (reason) =>
      `Refused to accept the proxy config: ${reason}. Accepting the rules takes a person at an interactive terminal (pipes, redirects, CI, and AI agents are refused)`,
  });
  const store = yield* ProxyAcceptStore;
  const key = yield* resolvedPath(input.path);
  const lookup = yield* store.lookup(key);
  if (lookup.state === "corrupt") {
    return yield* Effect.fail(corruptRecord(store.filePath));
  }
  const same = lookup.state === "found" && lookup.accepted.content === input.content;
  const outcome: "first use" | "changed" | "project added" | "unchanged" = same
    ? lookup.accepted.projectIds.includes(input.projectId)
      ? "unchanged"
      : "project added"
    : lookup.state === "missing"
      ? "first use"
      : "changed";
  const nowMs = yield* Clock.currentTimeMillis;
  if (outcome !== "unchanged") {
    const projectIds = same ? [...lookup.accepted.projectIds, input.projectId] : [input.projectId];
    yield* store.accept(key, { content: input.content, acceptedAtMs: nowMs, projectIds });
  }
  yield* store.markBrokered(input.projectId, { configPath: key, markedAtMs: nowMs });
  return outcome;
});

export const markProjectBrokered = Effect.fn("proxy-accept.markProjectBrokered")(function* (input: {
  readonly projectId: ProjectId;
  readonly configPath: string;
}): Effect.fn.Return<void, CliError, ProxyAcceptStore> {
  const store = yield* ProxyAcceptStore;
  const key = yield* resolvedPath(input.configPath);
  const markedAtMs = yield* Clock.currentTimeMillis;
  yield* store.markBrokered(input.projectId, { configPath: key, markedAtMs });
});

export const ensurePlainRunOfBrokeredProjectAllowed = Effect.fn(
  "proxy-accept.ensurePlainRunOfBrokeredProjectAllowed",
)(function* (
  projectId: ProjectId,
): Effect.fn.Return<void, CliError, ProxyAcceptStore | Stdio.Stdio | CliIo> {
  const store = yield* ProxyAcceptStore;
  const lookup = yield* store.brokeredProject(projectId);
  if (lookup.state === "corrupt") {
    return yield* Effect.fail(corruptRecord(store.filePath));
  }
  if (lookup.state === "missing") {
    return;
  }
  const where = `this project is brokered on this machine (its proxy config ${lookup.mark.configPath} was accepted) and no proxy config is in the working directory`;
  yield* ensureHumanCeremonyAllowed({
    agentRefusal: (detected) =>
      `Refused to run with the real values: an AI agent environment was detected${detected}, and ${where}. Run the command from the repository that holds the proxy config so the values are brokered, or a person runs it from a terminal`,
    terminalRefusal: (reason) =>
      `Refused to run with the real values: ${reason}, and ${where}. Run the command from the repository that holds the proxy config so the values are brokered, or run it yourself in a terminal`,
  });
  yield* logNote(`${where}; injecting the real values`);
});
