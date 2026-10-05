// The repository config of `maruhi proxy run` (PF4 — pf4-design.md
// ruling P5 "where the brokering rules live"): `maruhi.proxy.json`.
//
// The rules say, per variable, what the child process gets: a
// **placeholder** that the proxy swaps for the real value only toward the
// listed hosts (`broker`), a short-lived credential minted by a connector
// from other variables the child never sees (`connector`), the real value
// (`passthrough` — values a proxy cannot substitute, such as a database
// URL), or nothing (`withhold`). Variables the config does not name follow
// `unlisted` (default `withhold` — fail closed); hosts no rule names
// follow `unmatched` (default `allow` — tunnelled untouched, never
// inspected).
//
// Nothing in the file is a secret: it names variables and hosts, the same
// class of non-secret repository config as `maruhi.sync.json` (CLAUDE.md:
// non-secret configuration may be persisted). It does decide which host
// receives which value, so the docs say to review edits like a CI
// workflow, and `proxy run` prints the rules it loaded before starting
// the child. Same discipline as sync-config.ts: one JSON file (default
// `maruhi.proxy.json`, `--config` overrides), a version field, unknown
// keys refused, and validation wording that names the key and the rule
// but never echoes the value typed.
//
// The JSON is read in one pass of steps over Schema-decoded leaves
// (String / Literals / Record / Array), in the sequence the hand-written
// checks ran (the first reason wins, like before); config-schema.ts renders
// the failing issue as the same path-and-reason wording.

import { Effect, Result, Schema } from "effect";

import {
  at,
  configHeader,
  decode,
  envNameLeaf,
  field,
  type Invalid,
  knownKeys,
  loadConfig,
  nullishOr,
  objectLeaf,
  type Parsed,
  parseConfigDocument,
  refuse,
  stringLeaf,
  undefinedOr,
} from "../config-schema.ts";
import { type CliError, usageError } from "../errors.ts";
import { loadIfPresent } from "../json-record.ts";
import { SAFE_ENV_NAME } from "../run.ts";

/** Default location of the proxy config, relative to the working directory. */
export const DEFAULT_PROXY_CONFIG_PATH = "maruhi.proxy.json";

/** Where in a request a placeholder is substituted (RFC 9110 vocabulary). */
export type Surface = "header" | "path" | "query" | "body";

const SURFACES: readonly Surface[] = ["header", "path", "query", "body"];

/** The default surfaces (headers only — a token in a stored body could be published by the API; opt in per rule). */
const DEFAULT_SURFACES: readonly Surface[] = ["header"];

/**
 * One destination a rule allows: scheme (`https` unless written `http://`),
 * a host name (exact, or a `*.` prefix matching one or more labels) or an
 * IPv4 literal, and a port (the scheme's default unless written).
 */
export interface HostPattern {
  readonly scheme: "https" | "http";
  /** Lower-cased. For a wildcard, the part after `*.`. */
  readonly host: string;
  readonly wildcard: boolean;
  readonly port: number;
}

/** The connectors that mint a short-lived credential (proxy-connector.ts implements them). */
export type ConnectorKind = "github-app";

const CONNECTOR_KINDS: readonly ConnectorKind[] = ["github-app"];

/** The brokering settings shared by `broker` and `connector` rules. */
export interface BrokerSettings {
  readonly hosts: readonly HostPattern[];
  readonly surfaces: readonly Surface[];
  /** A fixed placeholder (for clients that validate the credential's format); undefined = a random one per run. */
  readonly placeholder: string | undefined;
}

export type VariableRule =
  | ({ readonly mode: "broker" } & BrokerSettings)
  | ({
      readonly mode: "connector";
      readonly connector: ConnectorKind;
      /** Connector input name → the maruhi variable that supplies it (consumed by the proxy, never injected). */
      readonly inputs: Readonly<Record<string, string>>;
    } & BrokerSettings)
  | { readonly mode: "passthrough" }
  | { readonly mode: "withhold" };

export interface ProxyConfig {
  readonly version: 1;
  /** The project the config belongs to (optional; checked against the resolved project when present). */
  readonly projectId: string | undefined;
  /** Destinations no rule names: tunnelled as they are, or refused. */
  readonly unmatched: "allow" | "block";
  /** Variables the config does not name. */
  readonly unlisted: "withhold" | "passthrough";
  /** Env-var name → rule. */
  readonly variables: ReadonlyMap<string, VariableRule>;
}

const ROOT_KEYS = ["version", "project", "unmatched", "unlisted", "variables"] as const;
const BROKER_KEYS = ["mode", "hosts", "surfaces", "placeholder"] as const;
const CONNECTOR_KEYS = ["mode", "connector", "inputs", "hosts", "surfaces", "placeholder"] as const;
const BARE_KEYS = ["mode"] as const;

/** The inputs each connector requires (names are the connector's vocabulary; values are variable names). */
const CONNECTOR_INPUTS: Readonly<Record<ConnectorKind, readonly string[]>> = {
  "github-app": ["appId", "privateKey", "installationId"],
};

// A DNS label sequence (lower-cased on parse). IPv4 literals also pass this shape
const HOST_NAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;
// Printable ASCII without spaces (a value that survives headers, URLs, and
// shells), long enough not to occur in ordinary traffic by accident (a
// short word as a placeholder would be rewritten wherever it appears —
// review finding §19 C-12)
const PLACEHOLDER = /^[\x21-\x7E]{16,256}$/;

/**
 * `localhost`, any name under `.localhost` (RFC 6761 — with or without a
 * wildcard: `*.localhost`, `app.localhost`, `*.app.localhost`), or a
 * 127.0.0.0/8 literal (never a wildcard).
 */
function isLoopbackHost(host: string, wildcard: boolean): boolean {
  if (host === "localhost" || host.endsWith(".localhost")) {
    return true;
  }
  return !wildcard && /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Parses one host entry: `[scheme://]host[:port]`, `*.` wildcard allowed
 * (`http://` only toward the loopback). Exported for tests.
 */
/** `[scheme://]rest` → the scheme and what follows it. */
function splitScheme(
  text: string,
): { readonly scheme: HostPattern["scheme"]; readonly rest: string } | Invalid {
  if (text.startsWith("https://")) {
    return { scheme: "https", rest: text.slice("https://".length) };
  }
  if (text.startsWith("http://")) {
    return { scheme: "http", rest: text.slice("http://".length) };
  }
  return text.includes("://")
    ? "the scheme must be https (the default) or http"
    : { scheme: "https", rest: text };
}

/** `host[:port]` → the host and the port (the scheme's default when absent). */
function splitPort(
  text: string,
  defaultPort: number,
): { readonly host: string; readonly port: number } | Invalid {
  const colon = text.lastIndexOf(":");
  if (colon < 0) {
    return { host: text, port: defaultPort };
  }
  const portText = text.slice(colon + 1);
  if (!/^\d{1,5}$/.test(portText) || Number(portText) < 1 || Number(portText) > 65535) {
    return "the port must be a number between 1 and 65535";
  }
  return { host: text.slice(0, colon), port: Number(portText) };
}

export function parseHostPattern(text: string): HostPattern | Invalid {
  const schemed = splitScheme(text.trim().toLowerCase());
  if (typeof schemed === "string") {
    return schemed;
  }
  const { scheme } = schemed;
  if (schemed.rest.includes("/")) {
    return "a host entry carries no path (write host[:port] only)";
  }
  const ported = splitPort(schemed.rest, scheme === "https" ? 443 : 80);
  if (typeof ported === "string") {
    return ported;
  }
  const { port } = ported;
  let rest = ported.host;
  let wildcard = false;
  if (rest.startsWith("*.")) {
    wildcard = true;
    rest = rest.slice(2);
  }
  if (rest.length === 0 || rest.length > 253 || !HOST_NAME.test(rest)) {
    return "the host must be a DNS name (letters, digits, `-`, `.`), optionally prefixed with `*.`, or an IPv4 address";
  }
  // `*.localhost` is the one single-label wildcard (every name under it is
  // the loopback — RFC 6761); `*.com` would name the public suffix
  if (wildcard && !rest.includes(".") && rest !== "localhost") {
    return "a wildcard needs at least two labels after `*.` (for example `*.example.com`; `*.localhost` is the exception)";
  }
  // A value substituted into plain HTTP travels in cleartext; only the
  // loopback is acceptable for that (a local development server)
  if (scheme === "http" && !isLoopbackHost(rest, wildcard)) {
    return "plain http:// is accepted only for loopback hosts (localhost, *.localhost, 127.0.0.0/8); a value toward any other host must travel over https";
  }
  return { scheme, host: rest, wildcard, port };
}

/** The `hosts` array: non-empty (each entry is then read in order by {@link parseHostPattern}). */
const HOSTS_MESSAGE = " must be a non-empty array of host entries";
const HOSTS = Schema.Array(Schema.Unknown)
  .annotate({ message: HOSTS_MESSAGE })
  .check(Schema.isMinLength(1, { message: HOSTS_MESSAGE }));

/** One `hosts` entry before it is read as a pattern. */
const HOST_ENTRY = Schema.String.annotate({
  message: " entries must be strings (host[:port], optionally with http:// or https://)",
});

/** The `surfaces` array: non-empty, each entry one of the RFC 9110 surfaces (deduped on success). */
const SURFACES_MESSAGE = ` must be a non-empty array of ${SURFACES.join(" | ")}`;
const SURFACES_FIELD = undefinedOr(
  SURFACES_MESSAGE,
  Schema.Array(
    Schema.Literals(SURFACES).annotate({ message: ` accepts only ${SURFACES.join(" | ")}` }),
  )
    .annotate({ message: SURFACES_MESSAGE })
    .check(Schema.isMinLength(1, { message: SURFACES_MESSAGE })),
);

/** The `placeholder` string (16–256 printable ASCII without spaces — review finding §19 C-12). */
const PLACEHOLDER_MESSAGE = " must be 16 to 256 printable ASCII characters without spaces";
const PLACEHOLDER_FIELD = undefinedOr(
  PLACEHOLDER_MESSAGE,
  stringLeaf(PLACEHOLDER_MESSAGE, (value) => PLACEHOLDER.test(value)),
);

/** The rule `mode` word. */
const MODE = Schema.Literals(["broker", "connector", "passthrough", "withhold"]).annotate({
  message: " must be broker, connector, passthrough, or withhold",
});

/** The `connector` kind word. */
const CONNECTOR = Schema.Literals(CONNECTOR_KINDS).annotate({
  message: ` must be one of ${CONNECTOR_KINDS.join(", ")}`,
});

/** A connector input's value: the maruhi variable that supplies it. */
const INPUT_VARIABLE = envNameLeaf(" must name a maruhi variable (letters, digits, _)");

function parseHosts(record: Record<string, unknown>): Parsed<readonly HostPattern[]> {
  return Result.gen(function* () {
    const entries = yield* field(record, "hosts", HOSTS);
    const hosts: HostPattern[] = [];
    for (const entry of entries) {
      // Entry by entry, like before: the first bad entry decides the reason
      const parsed = parseHostPattern(yield* at(["hosts"], decode(HOST_ENTRY, entry)));
      if (typeof parsed === "string") {
        return yield* refuse(` has an invalid entry: ${parsed}`, ["hosts"]);
      }
      hosts.push(parsed);
    }
    return hosts;
  });
}

function parseBrokerSettings(record: Record<string, unknown>): Parsed<BrokerSettings> {
  return Result.gen(function* () {
    const hosts = yield* parseHosts(record);
    const surfaces = yield* field(record, "surfaces", SURFACES_FIELD);
    const placeholder = yield* field(record, "placeholder", PLACEHOLDER_FIELD);
    return {
      hosts,
      surfaces: surfaces === undefined ? DEFAULT_SURFACES : [...new Set(surfaces)],
      placeholder,
    };
  });
}

function parseConnectorInputs(
  connector: ConnectorKind,
  record: Record<string, unknown>,
): Parsed<Readonly<Record<string, string>>> {
  const required = CONNECTOR_INPUTS[connector];
  const inputs = Result.gen(function* () {
    const given = yield* decode(
      objectLeaf(` must be an object naming the variables for ${required.join(", ")}`),
      record["inputs"],
    );
    yield* knownKeys(given, required, `the ${connector} connector takes ${required.join(", ")}`);
    const parsed: Record<string, string> = {};
    for (const key of required) {
      parsed[key] = yield* field(given, key, INPUT_VARIABLE);
    }
    return parsed;
  });
  return at(["inputs"], inputs);
}

function parseBrokerRule(value: Record<string, unknown>): Parsed<VariableRule> {
  return Result.gen(function* () {
    yield* knownKeys(value, BROKER_KEYS, `a broker rule accepts ${BROKER_KEYS.join(", ")}`);
    const settings = yield* parseBrokerSettings(value);
    return { mode: "broker", ...settings };
  });
}

function parseConnectorRule(value: Record<string, unknown>): Parsed<VariableRule> {
  return Result.gen(function* () {
    yield* knownKeys(
      value,
      CONNECTOR_KEYS,
      `a connector rule accepts ${CONNECTOR_KEYS.join(", ")}`,
    );
    const connector = yield* field(value, "connector", CONNECTOR);
    const inputs = yield* parseConnectorInputs(connector, value);
    const settings = yield* parseBrokerSettings(value);
    return { mode: "connector", connector, inputs, ...settings };
  });
}

function parseBareRule(
  mode: "passthrough" | "withhold",
  value: Record<string, unknown>,
): Parsed<VariableRule> {
  return Result.map(knownKeys(value, BARE_KEYS, `a ${mode} rule takes only "mode"`), () => ({
    mode,
  }));
}

const RULE_RECORD = objectLeaf(
  ' must be an object with a "mode", an array of hosts, or "passthrough" / "withhold"',
);

function parseRule(value: unknown): Parsed<VariableRule> {
  // Shorthands: an array = broker toward these hosts; a bare mode word
  if (Array.isArray(value)) {
    return parseRule({ mode: "broker", hosts: value });
  }
  if (value === "passthrough" || value === "withhold") {
    return Result.succeed({ mode: value });
  }
  return Result.gen(function* () {
    const record = yield* decode(RULE_RECORD, value);
    const mode = yield* field(record, "mode", MODE);
    switch (mode) {
      case "broker":
        return yield* parseBrokerRule(record);
      case "connector":
        return yield* parseConnectorRule(record);
      case "passthrough":
      case "withhold":
        return yield* parseBareRule(mode, record);
    }
  });
}

/** The top-level `unmatched` / `unlisted` words (null = absent = the default). */
const UNMATCHED_MESSAGE = ' must be "allow" (tunnel hosts no rule names, untouched) or "block"';
const UNMATCHED = nullishOr(
  UNMATCHED_MESSAGE,
  Schema.Literals(["allow", "block"]).annotate({ message: UNMATCHED_MESSAGE }),
);
const UNLISTED_MESSAGE =
  ' must be "withhold" (variables no rule names are not injected) or "passthrough"';
const UNLISTED = nullishOr(
  UNLISTED_MESSAGE,
  Schema.Literals(["withhold", "passthrough"]).annotate({ message: UNLISTED_MESSAGE }),
);

const VARIABLES_RECORD = objectLeaf(" must be an object (env-var name → rule); it may be empty");

/** The `variables` object: every rule, unique placeholders, and no injection of a consumed input. */
function parseVariables(
  record: Record<string, unknown>,
): Parsed<ReadonlyMap<string, VariableRule>> {
  const variables = Result.gen(function* () {
    const raw = yield* decode(VARIABLES_RECORD, record["variables"]);
    const rules = new Map<string, VariableRule>();
    const placeholders = new Set<string>();
    const consumed = new Map<string, string>();
    for (const [name, value] of Object.entries(raw)) {
      if (!SAFE_ENV_NAME.test(name)) {
        return yield* refuse(
          "variables keys must be environment variable names (letters, digits, _, starting with a letter or _)",
        );
      }
      const rule = yield* at([name], parseRule(value));
      yield* registerRule(name, rule, placeholders, consumed);
      rules.set(name, rule);
    }
    yield* checkConsumed(rules, consumed);
    return rules;
  });
  return at(["variables"], variables);
}

/** Tracks a rule's placeholder (unique across rules) and the inputs its connector consumes. */
function registerRule(
  name: string,
  rule: VariableRule,
  placeholders: Set<string>,
  consumed: Map<string, string>,
): Parsed<void> {
  if ((rule.mode === "broker" || rule.mode === "connector") && rule.placeholder !== undefined) {
    // One placeholder inside another would make the longer one's substitution
    // rewrite the shorter one's — refused, like a duplicate
    for (const other of placeholders) {
      if (other.includes(rule.placeholder) || rule.placeholder.includes(other)) {
        return refuse(
          `variables.${name}.placeholder is also used by another rule, or contains / is contained in another rule's placeholder (placeholders must be unique and independent)`,
        );
      }
    }
    placeholders.add(rule.placeholder);
  }
  if (rule.mode === "connector") {
    for (const [input, variable] of Object.entries(rule.inputs)) {
      consumed.set(variable, `${name}.inputs.${input}`);
    }
  }
  return Result.succeed(undefined);
}

/** A variable a connector consumes is never injected, so a rule that would inject it contradicts the connector. */
function checkConsumed(
  variables: ReadonlyMap<string, VariableRule>,
  consumed: ReadonlyMap<string, string>,
): Parsed<void> {
  for (const [variable, where] of consumed) {
    const rule = variables.get(variable);
    if (rule !== undefined && rule.mode !== "withhold") {
      return refuse(
        `variables.${variable} is consumed by a connector (${where}) and cannot also have a ${rule.mode} rule — a connector's inputs never reach the child`,
      );
    }
  }
  return Result.succeed(undefined);
}

/**
 * The document in one pass: the header fields, then the rules — the same
 * order the reasons ran in before (the first one wins).
 */
function parseProxyDocument(record: Record<string, unknown>): Parsed<ProxyConfig> {
  return Result.gen(function* () {
    const header = yield* configHeader(record, ROOT_KEYS);
    const unmatched = yield* field(record, "unmatched", UNMATCHED);
    const unlisted = yield* field(record, "unlisted", UNLISTED);
    const variables = yield* parseVariables(record);
    const config: ProxyConfig = {
      version: 1,
      projectId: header.projectId,
      unmatched: unmatched ?? "allow",
      unlisted: unlisted ?? "withhold",
      variables,
    };
    return config;
  });
}

/** Interpreting the config JSON (the reason's string when invalid). Exported for tests. */
export function parseProxyConfig(content: string): ProxyConfig | Invalid {
  return parseConfigDocument(content, parseProxyDocument);
}

/** A config as read from disk: the rules, and the exact content a person accepts (proxy-accept.ts). */
export interface LoadedProxyConfig {
  readonly config: ProxyConfig;
  readonly content: string;
}

/** Loading and verifying `--config <file>` (default `maruhi.proxy.json`). */
export function loadProxyConfig(path: string): Effect.Effect<LoadedProxyConfig, CliError> {
  return loadConfig(
    path,
    "proxy config",
    "Create it (see the Credential brokering page in the docs), or pass --config <file>",
    parseProxyConfig,
  ).pipe(Effect.map(({ parsed, content }) => ({ config: parsed, content })));
}

/**
 * The default config when it exists in the working directory (`maruhi run`
 * applies it without being told — ADR-0016 decision 7 revision 2): null
 * when the file is absent, and the same errors as {@link loadProxyConfig}
 * when it exists but cannot be read or is invalid — a broken config is
 * reported, never skipped (skipping would silently inject real values).
 */
export function loadProxyConfigIfPresent(
  path: string,
): Effect.Effect<LoadedProxyConfig | null, CliError> {
  return loadIfPresent(
    path,
    loadProxyConfig,
    `Cannot read the proxy config ${path} (it exists but is not readable). Fix it, or run with --plain from a terminal to inject the values directly`,
  );
}

/** Matching the config's `project` against the flag (a mismatch is a writing mistake = 2). */
export function checkProxyConfigProject(
  config: ProxyConfig,
  projectFlag: string | undefined,
): Effect.Effect<void, CliError> {
  if (
    config.projectId !== undefined &&
    projectFlag !== undefined &&
    projectFlag !== config.projectId
  ) {
    return Effect.fail(
      usageError(
        "--project does not match the `project` in the proxy config (the config belongs to a different project)",
      ),
    );
  }
  return Effect.void;
}
