// Acceptance of a proxy config by a person (pf4-design.md §21 R-8 / R-13 /
// R-14 — the answer to "an agent rewrites, deletes, or sidesteps
// `maruhi.proxy.json`").
//
// The repository's proxy config decides what a child receives (ADR-0016
// decision 7 revision 2): placeholders, pass-through values, withheld
// variables. An agent working in the repository can edit that file — set
// `unlisted: passthrough`, add a host it controls — or remove it, or run
// from another directory, and `maruhi run` again would hand it the
// plaintext the `--plain` ceremony denies. So:
//
// 1. A config is **applied only once a person has accepted it** with
//    `maruhi proxy accept`, the way direnv applies an `.envrc` only after
//    `direnv allow`: the accepted file's content is recorded here, per
//    user, outside the repository
//    (<account home>/.config/maruhi/proxy-accepted.json), **for the
//    project it was accepted for** (R-24 — a permissive file accepted for
//    one project must not be pointed at another with `--config`). A
//    config whose content matches its record for the project is applied by
//    anyone; one that is new, has changed, or was accepted for another
//    project is refused — at a terminal too — with a message naming the
//    command. Accepting is a human ceremony (the
//    evidence of the value-display gate: no known agent, stdin and stdout
//    terminals) and an explicit act, never a side effect of an unrelated
//    run (an agent's rewrite would otherwise ride the person's next
//    `maruhi run` — review finding R-14).
// 2. Every brokered run **marks its project as brokered on this machine**.
//    Plain `maruhi run` for a marked project without a config in the
//    working directory (the file deleted, or another directory) is then
//    gated like `--plain`: a person at a terminal may inject the real
//    values, an agent or a pipe is refused (R-13).
//
// What this is: a bar raised from "edit one file in the repository" to
// "edit a file outside the repository that nothing in the repository points
// at" — meaningful against a prompt-injected agent, which works in the
// repository. What it is not: a boundary against a hostile same-user
// process (that remains the sandbox shape). The structural successor is
// the config's hash recorded on the project's chain (signed rules — a
// follow-up on the ROADMAP), which an agent cannot forge; the ceremony
// here is its local precursor with the same UX (a person accepts the rules).
//
// Non-secret by construction (the config names variables and hosts, never
// values; project IDs are public identifiers); the content is stored
// verbatim rather than hashed so the record needs no cryptography and a
// mismatch can be explained. Same file discipline as the fingerprint
// ledger: 0600, atomic rename, a corrupt or unreadable file is never
// overwritten. The file lives under the account's home as the system user
// database gives it — not under `MARUHI_CONFIG_DIR` / `XDG_CONFIG_HOME`,
// which an agent can set for its own invocation (R-23).

import { dirname, join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { Context, Effect, FileSystem, Result, Schema, Stdio } from "effect";

import { AgentProfileRef, describeNonTerminal, ensureHumanCeremonyAllowed } from "../agent-gate.ts";
import { cliError, type CliError } from "../errors.ts";
import type { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";

/** One accepted config: the content a person accepted, when, and for which projects (R-24). */
export interface AcceptedProxyConfig {
  readonly content: string;
  readonly acceptedAtMs: number;
  readonly projectIds: readonly string[];
}

/** A project a brokered run has used on this machine (which config, and when first seen). */
export interface BrokeredProject {
  readonly configPath: string;
  readonly markedAtMs: number;
}

/** Load result (`corrupt` is distinguishable from `missing` — a person deals with it). */
export type AcceptedLookup =
  | { readonly state: "found"; readonly accepted: AcceptedProxyConfig }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

/** The brokered-project mark's load result (same three states — a corrupt record fails the gate closed). */
export type BrokeredLookup =
  | { readonly state: "found"; readonly mark: BrokeredProject }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

export interface ProxyAcceptStoreShape {
  readonly filePath: string;
  /** The record for a config file (keyed by its resolved absolute path). */
  readonly lookup: (configPath: string) => Effect.Effect<AcceptedLookup, CliError>;
  /** Records `content` as accepted for `configPath` (read-merge-write). Refuses to overwrite a corrupt file. */
  readonly accept: (
    configPath: string,
    accepted: AcceptedProxyConfig,
  ) => Effect.Effect<void, CliError>;
  /** The brokered-project mark (`missing` = never brokered here; `corrupt` is reported by the gate, never read as "never brokered"). */
  readonly brokeredProject: (projectId: string) => Effect.Effect<BrokeredLookup, CliError>;
  /** Marks a project as brokered on this machine (idempotent; keeps the first mark). */
  readonly markBrokered: (
    projectId: string,
    mark: BrokeredProject,
  ) => Effect.Effect<void, CliError>;
}

export class ProxyAcceptStore extends Context.Service<ProxyAcceptStore, ProxyAcceptStoreShape>()(
  "cli/ProxyAcceptStore",
) {}

/**
 * The record's location: `<account home>/.config/maruhi/proxy-accepted.json`.
 * Deliberately **not** the config directory the CLI otherwise uses: that
 * one follows `MARUHI_CONFIG_DIR` / `XDG_CONFIG_HOME`, and an agent
 * limited to the repository can set an environment variable for its own
 * invocation, point the record at a directory it writes, and apply its
 * own rules (review finding §21 R-23). `home` is the account's home from
 * the system user database (live.ts), which no environment variable moves.
 */
export function acceptedProxyConfigsPathOf(home: string): string {
  return join(home, ".config", "maruhi", "proxy-accepted.json");
}

/**
 * The ledger's Schema (strict — no partial reads, same as pins / the
 * fingerprint ledger): one bad entry fails the whole file as corrupt.
 * Extra keys on an entry or on the file are tolerated, as before.
 */
const LEDGER = Schema.fromJsonString(
  Schema.Struct({
    v: Schema.Literal(1),
    accepted: Schema.Record(
      Schema.String,
      Schema.Struct({
        content: Schema.String,
        acceptedAtMs: Schema.Int,
        projectIds: Schema.Array(Schema.String),
      }),
    ),
    projects: Schema.Record(
      Schema.String,
      Schema.Struct({
        configPath: Schema.String,
        markedAtMs: Schema.Int,
      }),
    ),
  }),
);

type AcceptedFile = (typeof LEDGER)["Type"];

const EMPTY_FILE: AcceptedFile = { v: 1, accepted: {}, projects: {} };

export function makeFileProxyAcceptStore(path: string): ProxyAcceptStoreShape {
  const loadRaw = (): Effect.Effect<LedgerRead> =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const content = yield* fs
        .readFileString(path, "utf8")
        .pipe(
          Effect.catch((error) =>
            (error.reason as unknown as Record<string, unknown>)["_tag"] === "NotFound"
              ? Effect.succeed(null)
              : Effect.succeed(false),
          ),
        );
      if (content === null) {
        return { state: "missing" as const };
      }
      if (content === false) {
        return { state: "corrupt" as const };
      }
      const decoded = Schema.decodeUnknownResult(LEDGER)(content);
      return Result.isSuccess(decoded)
        ? { state: "loaded" as const, file: decoded.success }
        : { state: "corrupt" as const };
    }).pipe(Effect.provide(BunFileSystem.layer));

  const write = (file: AcceptedFile): Effect.Effect<void, unknown> =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      yield* fs.makeDirectory(dirname(path), { recursive: true, mode: 0o700 });
      const temp = `${path}.${process.pid}.tmp`;
      yield* fs.writeFileString(temp, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
      yield* fs.rename(temp, path);
    }).pipe(Effect.provide(BunFileSystem.layer));

  const cannotRecord = (what: string): CliError =>
    cliError(
      `Cannot record ${what} (the record is corrupt, unreadable, or cannot be written): ${path} — inspect it, and if the modification was unintended, delete it and re-run`,
    );

  /** Read-merge-write; a corrupt (or unreadable) file is never overwritten. */
  const merge = (apply: (file: AcceptedFile) => AcceptedFile, what: string) =>
    Effect.gen(function* () {
      const loaded = yield* loadRaw();
      if (loaded.state === "corrupt") {
        return yield* Effect.fail(cannotRecord(what));
      }
      const file = apply(loaded.state === "missing" ? EMPTY_FILE : loaded.file);
      yield* write(file).pipe(Effect.mapError(() => cannotRecord(what)));
    });

  return {
    filePath: path,
    lookup: (configPath) =>
      Effect.gen(function* () {
        const loaded = yield* loadRaw();
        if (loaded.state !== "loaded") {
          return loaded;
        }
        const accepted = Object.hasOwn(loaded.file.accepted, configPath)
          ? loaded.file.accepted[configPath]
          : undefined;
        return accepted === undefined ? { state: "missing" } : { state: "found", accepted };
      }),
    accept: (configPath, accepted) =>
      merge(
        (file) => ({ ...file, accepted: { ...file.accepted, [configPath]: accepted } }),
        "the accepted proxy config",
      ),
    brokeredProject: (projectId) =>
      Effect.gen(function* () {
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

/** A ledger read (the same three states as the lookups — never fails; a read error is `corrupt`). */
type LedgerRead =
  | { readonly state: "missing" }
  | { readonly state: "corrupt" }
  | { readonly state: "loaded"; readonly file: AcceptedFile };

const ACCEPT_COMMAND = "`maruhi proxy accept`";

/** The resolved absolute path of the config (the record's key; `./x` and `--config /…/x` are one entry). */
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

/** Who may accept, and how — the tail of every refusal of an unaccepted config. */
function howToAccept(): Effect.Effect<string, never, Stdio.Stdio> {
  return Effect.gen(function* () {
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
}

/**
 * The acceptance rule for the config about to be applied: a content match
 * with the record passes silently; anything else is refused before any
 * network or decryption, naming who can accept it and how. `path` is the
 * path as the user wrote it (for messages).
 */
export function ensureProxyConfigAccepted(input: {
  readonly path: string;
  readonly content: string;
  /** The project whose values the config is about to govern — the acceptance must name it (R-24). */
  readonly projectId: string;
}): Effect.Effect<void, CliError, ProxyAcceptStore | Stdio.Stdio> {
  return Effect.gen(function* () {
    const store = yield* ProxyAcceptStore;
    const lookup = yield* store.lookup(yield* resolvedPath(input.path));
    if (lookup.state === "corrupt") {
      return yield* Effect.fail(corruptRecord(store.filePath));
    }
    if (lookup.state === "found" && lookup.accepted.content === input.content) {
      if (lookup.accepted.projectIds.includes(input.projectId)) {
        return;
      }
      // Accepted as it is, but for another project: a permissive file accepted
      // elsewhere must not be pointed at this project's values (R-24)
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
  });
}

/**
 * `maruhi proxy accept`: a person at a terminal records the config's
 * content as accepted on this machine. Returns what changed (for the
 * command's own summary of the rules).
 */
export function acceptProxyConfig(input: {
  readonly path: string;
  readonly content: string;
  /** The project the config is for: marked as brokered on this machine at acceptance (R-18 — the gate must be armed before any run). */
  readonly projectId: string;
}): Effect.Effect<
  "first use" | "changed" | "project added" | "unchanged",
  CliError,
  ProxyAcceptStore | Stdio.Stdio
> {
  return Effect.gen(function* () {
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
    if (outcome !== "unchanged") {
      // A changed content starts the project list over: the acceptance is of this content, for these projects
      const projectIds = same
        ? [...lookup.accepted.projectIds, input.projectId]
        : [input.projectId];
      yield* store.accept(key, { content: input.content, acceptedAtMs: Date.now(), projectIds });
    }
    // Armed here, not at the first brokered run: between accepting and
    // running, deleting the file must already be gated (R-18)
    yield* store.markBrokered(input.projectId, { configPath: key, markedAtMs: Date.now() });
    return outcome;
  });
}

/**
 * A brokered run marks its project (idempotent — normally already marked
 * by `proxy accept`; this covers a config accepted for one project and
 * used under another `--project`). A mark that cannot be written is an
 * error: the mark is what gates the plain run later (R-18).
 */
export function markProjectBrokered(input: {
  readonly projectId: string;
  readonly configPath: string;
}): Effect.Effect<void, CliError, ProxyAcceptStore> {
  return Effect.gen(function* () {
    const store = yield* ProxyAcceptStore;
    const key = yield* resolvedPath(input.configPath);
    yield* store.markBrokered(input.projectId, { configPath: key, markedAtMs: Date.now() });
  });
}

/**
 * Plain `maruhi run` without a config in the working directory, for a
 * project a brokered run has used on this machine: injecting the real
 * values is gated like `--plain` (a person at a terminal; an agent or a
 * pipe is refused) — otherwise deleting `maruhi.proxy.json`, or running
 * from another directory, would be the shortest way around the rules
 * (review finding R-13). A project never brokered here is unchanged; a
 * record that cannot be read fails closed (it is reported, never taken as
 * "never brokered" — the R-15 discipline).
 */
export function ensurePlainRunOfBrokeredProjectAllowed(
  projectId: string,
): Effect.Effect<void, CliError, ProxyAcceptStore | Stdio.Stdio | CliIo> {
  return Effect.gen(function* () {
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
}
