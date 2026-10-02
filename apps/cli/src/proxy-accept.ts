// Acceptance of a proxy config by a person (pf4-design.md §21 R-8 — the
// answer to "an agent rewrites `maruhi.proxy.json`").
//
// The repository's proxy config decides what a child receives (ADR-0016
// decision 7 revision 2): placeholders, pass-through values, withheld
// variables. An agent working in the repository can edit that file — set
// `unlisted: passthrough`, add a host it controls to a rule — and run
// `maruhi run` again, which would hand it the plaintext the `--plain`
// ceremony denies. So a config is **applied only once a person has
// accepted it**, the way direnv applies an `.envrc` only after
// `direnv allow`: the accepted file's content is recorded here, per user,
// outside the repository (<config dir>/proxy-accepted.json); a config whose
// content matches its record is applied by anyone; one that is new or has
// changed is accepted — and recorded — when the evidence of a person at a
// terminal is present (the same evidence as the value-display gate: no
// known agent, stdin and stdout are terminals), and refused otherwise, with
// a message that says who can accept it and how.
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
// values); the content is stored verbatim rather than hashed so the record
// needs no cryptography and a mismatch can be explained. Same file
// discipline as the fingerprint ledger: 0600, atomic rename, a corrupt file
// is never overwritten.

import { mkdir, realpath, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { Context, Effect, Stdio } from "effect";

import { AgentProfileRef, describeNonTerminal } from "./agent-gate.ts";
import { cliError, type CliError } from "./errors.ts";
import type { CliIo } from "./io.ts";
import { isRecord, readLedger } from "./json-record.ts";
import { logNote } from "./notice.ts";

/** One accepted config (the content a person accepted, and when). */
export interface AcceptedProxyConfig {
  readonly content: string;
  readonly acceptedAtMs: number;
}

/** Load result (`corrupt` is distinguishable from `missing` — a person deals with it). */
export type AcceptedLookup =
  | { readonly state: "found"; readonly accepted: AcceptedProxyConfig }
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
}

export class ProxyAcceptStore extends Context.Service<ProxyAcceptStore, ProxyAcceptStoreShape>()(
  "cli/ProxyAcceptStore",
) {}

/** The record's location (same family as the config: <config.json's parent>/proxy-accepted.json). */
export function acceptedProxyConfigsPathOf(configPath: string): string {
  return join(dirname(configPath), "proxy-accepted.json");
}

interface AcceptedFile {
  readonly v: 1;
  readonly accepted: Readonly<Record<string, AcceptedProxyConfig>>;
}

function decodeAccepted(record: unknown): AcceptedProxyConfig | null {
  if (
    !isRecord(record) ||
    typeof record["content"] !== "string" ||
    typeof record["acceptedAtMs"] !== "number" ||
    !Number.isSafeInteger(record["acceptedAtMs"])
  ) {
    return null;
  }
  return { content: record["content"], acceptedAtMs: record["acceptedAtMs"] };
}

/** Strict decoding (no partial reads — same as pins / the fingerprint ledger). */
function decodeFile(json: string): AcceptedFile | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isRecord(parsed) || parsed["v"] !== 1 || !isRecord(parsed["accepted"])) {
    return null;
  }
  const accepted: Record<string, AcceptedProxyConfig> = {};
  for (const [path, record] of Object.entries(parsed["accepted"])) {
    const decoded = decodeAccepted(record);
    if (decoded === null) {
      return null;
    }
    accepted[path] = decoded;
  }
  return { v: 1, accepted };
}

export function makeFileProxyAcceptStore(path: string): ProxyAcceptStoreShape {
  const loadRaw = () => readLedger(path, decodeFile);

  const write = async (file: AcceptedFile): Promise<void> => {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const temp = `${path}.${process.pid}.tmp`;
    await writeFile(temp, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, path);
  };

  return {
    filePath: path,
    lookup: (configPath) =>
      Effect.promise(async () => {
        const loaded = await loadRaw();
        if (loaded.state !== "loaded") {
          return loaded;
        }
        const accepted = Object.hasOwn(loaded.file.accepted, configPath)
          ? loaded.file.accepted[configPath]
          : undefined;
        return accepted === undefined ? { state: "missing" } : { state: "found", accepted };
      }),
    accept: (configPath, accepted) =>
      Effect.tryPromise({
        try: async () => {
          const loaded = await loadRaw();
          if (loaded.state === "corrupt") {
            // Refuse overwriting a corrupt file (same discipline as the fingerprint ledger)
            throw new Error("corrupt");
          }
          const base: AcceptedFile =
            loaded.state === "missing" ? { v: 1, accepted: {} } : loaded.file;
          await write({ v: 1, accepted: { ...base.accepted, [configPath]: accepted } });
        },
        catch: () =>
          cliError(
            `Cannot record the accepted proxy config (corrupt or an I/O failure): ${path} — inspect it, and if the modification was unintended, delete it and re-run`,
          ),
      }),
  };
}

/** Why a new or changed config cannot be accepted right now (null = a person at a terminal is present). */
function acceptanceRefusal(input: {
  readonly path: string;
  readonly change: string;
}): Effect.Effect<string | null, never, Stdio.Stdio> {
  return Effect.gen(function* () {
    const agent = yield* AgentProfileRef;
    if (agent.isAgent) {
      const detected = agent.name === undefined ? "" : ` (${agent.name})`;
      return `Refused to apply the proxy config ${input.path}: ${input.change}, and an AI agent environment was detected${detected}. A person reviews the file and runs \`maruhi run\` once from a terminal to accept it (an agent cannot accept its own rules); until then the values are neither brokered nor injected`;
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal) {
      return `Refused to apply the proxy config ${input.path}: ${input.change}, and ${describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal })}. Accepting the rules takes a person at an interactive terminal: review the file and run \`maruhi run\` once there (pipes, redirects, CI, and AI agents cannot accept it)`;
    }
    return null;
  });
}

/**
 * Applies the acceptance rule to the config about to be used: a content
 * match with the record passes silently; otherwise the evidence of a
 * person at a terminal accepts (and records) it, and anything else is
 * refused before any network or decryption. `path` is the path as the
 * user wrote it (for messages); the record is keyed by its resolved
 * absolute path so `./maruhi.proxy.json` and `--config /…/maruhi.proxy.json`
 * are one entry.
 */
export function ensureProxyConfigAccepted(input: {
  readonly path: string;
  readonly content: string;
}): Effect.Effect<void, CliError, ProxyAcceptStore | Stdio.Stdio | CliIo> {
  return Effect.gen(function* () {
    const store = yield* ProxyAcceptStore;
    const key = yield* Effect.tryPromise({
      try: () => realpath(input.path),
      catch: () => cliError(`Cannot resolve the path of the proxy config ${input.path}`),
    });
    const lookup = yield* store.lookup(key);
    if (lookup.state === "corrupt") {
      return yield* Effect.fail(
        cliError(
          `The record of accepted proxy configs is corrupt: ${store.filePath} — inspect it, and if the modification was unintended, delete it and run \`maruhi run\` again from a terminal`,
        ),
      );
    }
    if (lookup.state === "found" && lookup.accepted.content === input.content) {
      return;
    }
    const change =
      lookup.state === "missing"
        ? "it has not been accepted on this machine yet"
        : "it has changed since a person last accepted it on this machine";
    const refusal = yield* acceptanceRefusal({ path: input.path, change });
    if (refusal !== null) {
      return yield* Effect.fail(cliError(refusal));
    }
    yield* store.accept(key, { content: input.content, acceptedAtMs: Date.now() });
    yield* logNote(
      `${input.path} accepted for brokering on this machine (${lookup.state === "missing" ? "first use" : "changed"}); the next change to the file will again need a person at a terminal`,
    );
  });
}
