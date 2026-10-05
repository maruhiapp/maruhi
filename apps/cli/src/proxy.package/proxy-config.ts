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
// The JSON is described with Schema and decoded with
// `Schema.decodeUnknownResult`: the leaf shapes are real schema nodes
// (String / Literals / Record / Array / Struct), and everything whose
// wording or ordering is conditional — the mode dispatch, the per-mode
// key sets, the cross-rule checks — is a `Schema.makeFilter` in the same
// sequence the hand-written checks ran (the first reason wins, like
// before). The filters report `Schema.FilterIssue`s: a `{path, issue}`
// whose issue starts with a separator is a suffix appended to the dotted
// path ("variables.X.mode" + " must be ..."), and a plain string is a
// complete reason; the wording is unchanged.

import { Effect, Result, Schema } from "effect";

import {
  envNameLeaf,
  field,
  type Invalid,
  isReason,
  issueReason,
  JsonRecord,
  loadConfig,
  type Reason,
  reasonIssue,
  stringLeaf,
  unknownKeysRefusal,
} from "../config-schema.ts";
import { type CliError, usageError } from "../errors.ts";
import { loadIfPresent, parseConfigHeader } from "../json-record.ts";

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

// An environment variable name (run.ts's SAFE_ENV_NAME — a POSIX identifier)
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
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

/** The `hosts` array: non-empty, string entries, each a valid host pattern (the entry index never reaches the reason). */
const HOSTS = Schema.Array(Schema.Unknown)
  .annotate({ message: " must be a non-empty array of host entries" })
  .check(
    Schema.makeFilter((entries) => {
      if (entries.length === 0) {
        return { path: [], issue: " must be a non-empty array of host entries" };
      }
      for (const entry of entries) {
        if (Result.isFailure(Schema.decodeUnknownResult(Schema.String)(entry))) {
          return {
            path: [],
            issue: " entries must be strings (host[:port], optionally with http:// or https://)",
          };
        }
      }
      return undefined;
    }),
  );

/** The `surfaces` array: non-empty, each entry one of the RFC 9110 surfaces (deduped on success). */
const SURFACES_FIELD = Schema.Array(Schema.Unknown)
  .annotate({ message: ` must be a non-empty array of ${SURFACES.join(" | ")}` })
  .check(
    Schema.makeFilter((entries) => {
      if (entries.length === 0) {
        return { path: [], issue: ` must be a non-empty array of ${SURFACES.join(" | ")}` };
      }
      for (const entry of entries) {
        const surface = Schema.decodeUnknownResult(Schema.String)(entry);
        if (
          Result.isFailure(surface) ||
          !(SURFACES as readonly string[]).includes(surface.success)
        ) {
          return { path: [], issue: ` accepts only ${SURFACES.join(" | ")}` };
        }
      }
      return undefined;
    }),
  );

/** The `placeholder` string (16–256 printable ASCII without spaces — review finding §19 C-12). */
const PLACEHOLDER_FIELD = stringLeaf(
  " must be 16 to 256 printable ASCII characters without spaces",
  (value) => PLACEHOLDER.test(value),
);

/** The rule `mode` word. */
const MODE = Schema.Literals(["broker", "connector", "passthrough", "withhold"]).annotate({
  message: " must be broker, connector, passthrough, or withhold",
});

/** The `connector` kind word. */
const CONNECTOR = Schema.Literals(CONNECTOR_KINDS).annotate({
  message: ` must be one of ${CONNECTOR_KINDS.join(", ")}`,
});

function parseHosts(name: string, value: unknown): readonly HostPattern[] | Reason {
  const entries = Schema.decodeUnknownResult(HOSTS)(value);
  if (Result.isFailure(entries)) {
    return { path: ["hosts"], issue: entries.failure.issue };
  }
  const hosts: HostPattern[] = [];
  for (const entry of entries.success) {
    // The schema checked every entry is a string
    const parsed = parseHostPattern(entry as string);
    if (typeof parsed === "string") {
      return { path: ["hosts"], issue: ` has an invalid entry: ${parsed}` };
    }
    hosts.push(parsed);
  }
  return hosts;
}

function parseSurfaces(record: Record<string, unknown>): readonly Surface[] | Reason {
  const entries = field(record, "surfaces", Schema.UndefinedOr(SURFACES_FIELD));
  if (isReason(entries)) {
    return entries;
  }
  if (entries.value === undefined) {
    return DEFAULT_SURFACES;
  }
  // The schema checked every entry is one of SURFACES (the set dedupes)
  return [...new Set(entries.value as readonly Surface[])];
}

function parsePlaceholder(
  record: Record<string, unknown>,
): { readonly placeholder: string | undefined } | Reason {
  const placeholder = field(record, "placeholder", Schema.UndefinedOr(PLACEHOLDER_FIELD));
  return isReason(placeholder) ? placeholder : { placeholder: placeholder.value };
}

function parseBrokerSettings(
  name: string,
  record: Record<string, unknown>,
): BrokerSettings | Reason {
  const hosts = parseHosts(name, record["hosts"]);
  if (isReason(hosts)) {
    return hosts;
  }
  const surfaces = parseSurfaces(record);
  if (isReason(surfaces)) {
    return surfaces;
  }
  const placeholder = parsePlaceholder(record);
  if (isReason(placeholder)) {
    return placeholder;
  }
  return { hosts, surfaces, placeholder: placeholder.placeholder };
}

function parseConnectorInputs(
  name: string,
  connector: ConnectorKind,
  value: unknown,
): Readonly<Record<string, string>> | Reason {
  const required = CONNECTOR_INPUTS[connector];
  const inputs = Schema.decodeUnknownResult(
    JsonRecord(` must be an object naming the variables for ${required.join(", ")}`),
  )(value);
  if (Result.isFailure(inputs)) {
    return { path: ["inputs"], issue: inputs.failure.issue };
  }
  const unknown = unknownKeysRefusal(
    inputs.success,
    required,
    `the ${connector} connector takes ${required.join(", ")}`,
  );
  if (unknown !== undefined) {
    return { path: ["inputs"], issue: reasonIssue(unknown) };
  }
  const parsed: Record<string, string> = {};
  for (const key of required) {
    const variable = field(
      inputs.success,
      key,
      envNameLeaf(" must name a maruhi variable (letters, digits, _)"),
    );
    if (isReason(variable)) {
      return { path: ["inputs"], issue: reasonIssue(variable) };
    }
    parsed[key] = variable.value;
  }
  return parsed;
}

function parseBrokerRule(name: string, value: Record<string, unknown>): VariableRule | Reason {
  const unknown = unknownKeysRefusal(
    value,
    BROKER_KEYS,
    `a broker rule accepts ${BROKER_KEYS.join(", ")}`,
  );
  if (unknown !== undefined) {
    return unknown;
  }
  const settings = parseBrokerSettings(name, value);
  return isReason(settings) ? settings : { mode: "broker", ...settings };
}

function parseConnectorRule(name: string, value: Record<string, unknown>): VariableRule | Reason {
  const unknown = unknownKeysRefusal(
    value,
    CONNECTOR_KEYS,
    `a connector rule accepts ${CONNECTOR_KEYS.join(", ")}`,
  );
  if (unknown !== undefined) {
    return unknown;
  }
  const connector = field(value, "connector", CONNECTOR);
  if (isReason(connector)) {
    return connector;
  }
  const inputs = parseConnectorInputs(name, connector.value, value["inputs"]);
  if (isReason(inputs)) {
    return inputs;
  }
  const settings = parseBrokerSettings(name, value);
  return isReason(settings)
    ? settings
    : { mode: "connector", connector: connector.value, inputs, ...settings };
}

function parseBareRule(
  name: string,
  mode: "passthrough" | "withhold",
  value: Record<string, unknown>,
): VariableRule | Reason {
  const unknown = unknownKeysRefusal(value, BARE_KEYS, `a ${mode} rule takes only "mode"`);
  return unknown === undefined ? { mode } : unknown;
}

function parseRule(name: string, value: unknown): VariableRule | Reason {
  // Shorthands: an array = broker toward these hosts; a bare mode word
  if (Array.isArray(value)) {
    return parseRule(name, { mode: "broker", hosts: value });
  }
  if (value === "passthrough" || value === "withhold") {
    return { mode: value };
  }
  return parseRecordRule(name, value);
}

function parseRecordRule(name: string, value: unknown): VariableRule | Reason {
  const record = Schema.decodeUnknownResult(
    JsonRecord(
      ' must be an object with a "mode", an array of hosts, or "passthrough" / "withhold"',
    ),
  )(value);
  if (Result.isFailure(record)) {
    return record.failure.issue;
  }
  const mode = field(record.success, "mode", MODE);
  if (isReason(mode)) {
    return mode;
  }
  switch (mode.value) {
    case "broker":
      return parseBrokerRule(name, record.success);
    case "connector":
      return parseConnectorRule(name, record.success);
    case "passthrough":
    case "withhold":
      return parseBareRule(name, mode.value, record.success);
  }
}

/** The top-level scalar fields (version / project / unmatched / unlisted). */
const UNMATCHED = Schema.NullishOr(
  Schema.Literals(["allow", "block"]).annotate({
    message: ' must be "allow" (tunnel hosts no rule names, untouched) or "block"',
  }),
);
const UNLISTED = Schema.NullishOr(
  Schema.Literals(["withhold", "passthrough"]).annotate({
    message: ' must be "withhold" (variables no rule names are not injected) or "passthrough"',
  }),
);

function parseRoot(
  parsed: Record<string, unknown>,
): Pick<ProxyConfig, "projectId" | "unmatched" | "unlisted"> | Reason {
  const header = parseConfigHeader(parsed, ROOT_KEYS);
  if (typeof header === "string") {
    return header;
  }
  const unmatched = field(parsed, "unmatched", UNMATCHED);
  if (isReason(unmatched)) {
    return unmatched;
  }
  const unlisted = field(parsed, "unlisted", UNLISTED);
  if (isReason(unlisted)) {
    return unlisted;
  }
  return {
    projectId: header.projectId,
    unmatched: unmatched.value ?? "allow",
    unlisted: unlisted.value ?? "withhold",
  };
}

/** The `variables` object: every rule, unique placeholders, and no injection of a consumed input. */
function parseVariables(raw: unknown): ReadonlyMap<string, VariableRule> | Reason {
  const record = Schema.decodeUnknownResult(
    JsonRecord(" must be an object (env-var name → rule); it may be empty"),
  )(raw);
  if (Result.isFailure(record)) {
    return record.failure.issue;
  }
  const variables = new Map<string, VariableRule>();
  const placeholders = new Set<string>();
  const consumed = new Map<string, string>();
  for (const [name, value] of Object.entries(record.success)) {
    if (!ENV_NAME.test(name)) {
      return "variables keys must be environment variable names (letters, digits, _, starting with a letter or _)";
    }
    const rule = parseRule(name, value);
    if (isReason(rule)) {
      return { path: [name], issue: reasonIssue(rule) };
    }
    const registered = registerRule(name, rule, placeholders, consumed);
    if (registered !== null) {
      return registered;
    }
    variables.set(name, rule);
  }
  return checkConsumed(variables, consumed) ?? variables;
}

/** Tracks a rule's placeholder (unique across rules) and the inputs its connector consumes. */
function registerRule(
  name: string,
  rule: VariableRule,
  placeholders: Set<string>,
  consumed: Map<string, string>,
): Invalid | null {
  if ((rule.mode === "broker" || rule.mode === "connector") && rule.placeholder !== undefined) {
    // One placeholder inside another would make the longer one's substitution
    // rewrite the shorter one's — refused, like a duplicate
    for (const other of placeholders) {
      if (other.includes(rule.placeholder) || rule.placeholder.includes(other)) {
        return `variables.${name}.placeholder is also used by another rule, or contains / is contained in another rule's placeholder (placeholders must be unique and independent)`;
      }
    }
    placeholders.add(rule.placeholder);
  }
  if (rule.mode === "connector") {
    for (const [input, variable] of Object.entries(rule.inputs)) {
      consumed.set(variable, `${name}.inputs.${input}`);
    }
  }
  return null;
}

/** A variable a connector consumes is never injected, so a rule that would inject it contradicts the connector. */
function checkConsumed(
  variables: ReadonlyMap<string, VariableRule>,
  consumed: ReadonlyMap<string, string>,
): Invalid | null {
  for (const [variable, where] of consumed) {
    const rule = variables.get(variable);
    if (rule !== undefined && rule.mode !== "withhold") {
      return `variables.${variable} is consumed by a connector (${where}) and cannot also have a ${rule.mode} rule — a connector's inputs never reach the child`;
    }
  }
  return null;
}

/**
 * The document as a Schema: a JSON object, then the header fields, then
 * the rules — the same order the reasons ran in before (the first one
 * wins). `parseConfigHeader` (json-record.ts) stays the header's check —
 * it returns the reason's string, which is a verbatim filter issue.
 */
const ProxyDocument = JsonRecord("the top level must be an object")
  .check(
    Schema.makeFilter((record) => {
      const root = parseRoot(record);
      return isReason(root) ? root : undefined;
    }),
  )
  .check(
    Schema.makeFilter((record) => {
      const variables = parseVariables(record["variables"]);
      return isReason(variables)
        ? { path: ["variables"], issue: reasonIssue(variables) }
        : undefined;
    }),
  );

/** Interpreting the config JSON (the reason's string when invalid). Exported for tests. */
export function parseProxyConfig(content: string): ProxyConfig | Invalid {
  const json = Schema.decodeUnknownResult(Schema.fromJsonString(Schema.Unknown))(content);
  if (Result.isFailure(json)) {
    return "not valid JSON";
  }
  const decoded = Schema.decodeUnknownResult(ProxyDocument)(json.success);
  if (Result.isFailure(decoded)) {
    return issueReason(decoded.failure.issue);
  }
  // The document's filters already ran the same pure steps — re-running
  // them on the validated record cannot produce a reason
  const parsed = parseProxyConfigDocument(decoded.success);
  if (isReason(parsed)) {
    throw new Error("proxy-config: the document passed validation but failed to build");
  }
  return parsed;
}

/** The fused validation + build pass over a validated record (its checks are the document's filters). */
function parseProxyConfigDocument(record: Record<string, unknown>): ProxyConfig | Reason {
  const root = parseRoot(record);
  if (isReason(root)) {
    return root;
  }
  const variables = parseVariables(record["variables"]);
  return isReason(variables) ? variables : { version: 1, ...root, variables };
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
