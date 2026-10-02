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

import { readFile, stat } from "node:fs/promises";

import { Effect } from "effect";

import { cliError, type CliError, usageError } from "./errors.ts";
import { isRecord, parseConfigHeader, parseJsonRecord, unknownKeys } from "./json-record.ts";

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

/** A validation failure (the reason). Never includes a typed value. */
type Invalid = string;

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

/** `localhost`, `*.localhost`, or a 127.0.0.0/8 literal. */
function isLoopbackHost(host: string, wildcard: boolean): boolean {
  if (host === "localhost") {
    return true;
  }
  if (wildcard) {
    return host === "localhost";
  }
  return host.endsWith(".localhost") || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
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
  if (wildcard && !rest.includes(".")) {
    return "a wildcard needs at least two labels after `*.` (for example `*.example.com`)";
  }
  // A value substituted into plain HTTP travels in cleartext; only the
  // loopback is acceptable for that (a local development server)
  if (scheme === "http" && !isLoopbackHost(rest, wildcard)) {
    return "plain http:// is accepted only for loopback hosts (localhost, *.localhost, 127.0.0.0/8); a value toward any other host must travel over https";
  }
  return { scheme, host: rest, wildcard, port };
}

function parseHosts(name: string, value: unknown): readonly HostPattern[] | Invalid {
  if (!Array.isArray(value) || value.length === 0) {
    return `variables.${name}.hosts must be a non-empty array of host entries`;
  }
  const hosts: HostPattern[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") {
      return `variables.${name}.hosts entries must be strings (host[:port], optionally with http:// or https://)`;
    }
    const parsed = parseHostPattern(entry);
    if (typeof parsed === "string") {
      return `variables.${name}.hosts has an invalid entry: ${parsed}`;
    }
    hosts.push(parsed);
  }
  return hosts;
}

function parseSurfaces(name: string, value: unknown): readonly Surface[] | Invalid {
  if (value === undefined) {
    return DEFAULT_SURFACES;
  }
  if (!Array.isArray(value) || value.length === 0) {
    return `variables.${name}.surfaces must be a non-empty array of ${SURFACES.join(" | ")}`;
  }
  const surfaces = new Set<Surface>();
  for (const entry of value) {
    if (typeof entry !== "string" || !(SURFACES as readonly string[]).includes(entry)) {
      return `variables.${name}.surfaces accepts only ${SURFACES.join(" | ")}`;
    }
    surfaces.add(entry as Surface);
  }
  return [...surfaces];
}

function parsePlaceholder(
  name: string,
  value: unknown,
): { readonly placeholder: string | undefined } | Invalid {
  if (value === undefined) {
    return { placeholder: undefined };
  }
  if (typeof value !== "string" || !PLACEHOLDER.test(value)) {
    return `variables.${name}.placeholder must be 16 to 256 printable ASCII characters without spaces`;
  }
  return { placeholder: value };
}

function parseBrokerSettings(
  name: string,
  record: Record<string, unknown>,
): BrokerSettings | Invalid {
  const hosts = parseHosts(name, record["hosts"]);
  if (typeof hosts === "string") {
    return hosts;
  }
  const surfaces = parseSurfaces(name, record["surfaces"]);
  if (typeof surfaces === "string") {
    return surfaces;
  }
  const placeholder = parsePlaceholder(name, record["placeholder"]);
  if (typeof placeholder === "string") {
    return placeholder;
  }
  return { hosts, surfaces, placeholder: placeholder.placeholder };
}

function parseConnectorInputs(
  name: string,
  connector: ConnectorKind,
  value: unknown,
): Readonly<Record<string, string>> | Invalid {
  const required = CONNECTOR_INPUTS[connector];
  if (!isRecord(value)) {
    return `variables.${name}.inputs must be an object naming the variables for ${required.join(", ")}`;
  }
  const unknown = unknownKeys(value, required);
  if (unknown.length > 0) {
    return `variables.${name}.inputs has unknown keys (${unknown.join(", ")}); the ${connector} connector takes ${required.join(", ")}`;
  }
  const inputs: Record<string, string> = {};
  for (const key of required) {
    const variable = value[key];
    if (typeof variable !== "string" || !ENV_NAME.test(variable)) {
      return `variables.${name}.inputs.${key} must name a maruhi variable (letters, digits, _)`;
    }
    inputs[key] = variable;
  }
  return inputs;
}

function parseBrokerRule(name: string, value: Record<string, unknown>): VariableRule | Invalid {
  const unknown = unknownKeys(value, BROKER_KEYS);
  if (unknown.length > 0) {
    return `variables.${name} has unknown keys (${unknown.join(", ")}); a broker rule accepts ${BROKER_KEYS.join(", ")}`;
  }
  const settings = parseBrokerSettings(name, value);
  return typeof settings === "string" ? settings : { mode: "broker", ...settings };
}

function parseConnectorRule(name: string, value: Record<string, unknown>): VariableRule | Invalid {
  const unknown = unknownKeys(value, CONNECTOR_KEYS);
  if (unknown.length > 0) {
    return `variables.${name} has unknown keys (${unknown.join(", ")}); a connector rule accepts ${CONNECTOR_KEYS.join(", ")}`;
  }
  const connector = value["connector"];
  if (
    typeof connector !== "string" ||
    !(CONNECTOR_KINDS as readonly string[]).includes(connector)
  ) {
    return `variables.${name}.connector must be one of ${CONNECTOR_KINDS.join(", ")}`;
  }
  const kind = connector as ConnectorKind;
  const inputs = parseConnectorInputs(name, kind, value["inputs"]);
  if (typeof inputs === "string") {
    return inputs;
  }
  const settings = parseBrokerSettings(name, value);
  return typeof settings === "string"
    ? settings
    : { mode: "connector", connector: kind, inputs, ...settings };
}

function parseBareRule(
  name: string,
  mode: "passthrough" | "withhold",
  value: Record<string, unknown>,
): VariableRule | Invalid {
  const unknown = unknownKeys(value, BARE_KEYS);
  if (unknown.length > 0) {
    return `variables.${name} has unknown keys (${unknown.join(", ")}); a ${mode} rule takes only "mode"`;
  }
  return { mode };
}

function parseRule(name: string, value: unknown): VariableRule | Invalid {
  // Shorthands: an array = broker toward these hosts; a bare mode word
  if (Array.isArray(value)) {
    return parseRule(name, { mode: "broker", hosts: value });
  }
  if (value === "passthrough" || value === "withhold") {
    return { mode: value };
  }
  if (!isRecord(value)) {
    return `variables.${name} must be an object with a "mode", an array of hosts, or "passthrough" / "withhold"`;
  }
  const mode = value["mode"];
  switch (mode) {
    case "broker":
      return parseBrokerRule(name, value);
    case "connector":
      return parseConnectorRule(name, value);
    case "passthrough":
    case "withhold":
      return parseBareRule(name, mode, value);
    default:
      return `variables.${name}.mode must be broker, connector, passthrough, or withhold`;
  }
}

/** The top-level scalar fields (version / project / unmatched / unlisted). */
function parseRoot(
  parsed: Record<string, unknown>,
): Pick<ProxyConfig, "projectId" | "unmatched" | "unlisted"> | Invalid {
  const header = parseConfigHeader(parsed, ROOT_KEYS);
  if (typeof header === "string") {
    return header;
  }
  const unmatched = parsed["unmatched"] ?? "allow";
  if (unmatched !== "allow" && unmatched !== "block") {
    return 'unmatched must be "allow" (tunnel hosts no rule names, untouched) or "block"';
  }
  const unlisted = parsed["unlisted"] ?? "withhold";
  if (unlisted !== "withhold" && unlisted !== "passthrough") {
    return 'unlisted must be "withhold" (variables no rule names are not injected) or "passthrough"';
  }
  return { projectId: header.projectId, unmatched, unlisted };
}

/** The `variables` object: every rule, unique placeholders, and no injection of a consumed input. */
function parseVariables(raw: unknown): ReadonlyMap<string, VariableRule> | Invalid {
  if (!isRecord(raw)) {
    return "variables must be an object (env-var name → rule); it may be empty";
  }
  const variables = new Map<string, VariableRule>();
  const placeholders = new Set<string>();
  const consumed = new Map<string, string>();
  for (const [name, value] of Object.entries(raw)) {
    if (!ENV_NAME.test(name)) {
      return "variables keys must be environment variable names (letters, digits, _, starting with a letter or _)";
    }
    const rule = parseRule(name, value);
    if (typeof rule === "string") {
      return rule;
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

/** Interpreting the config JSON (the reason's string when invalid). Exported for tests. */
export function parseProxyConfig(content: string): ProxyConfig | Invalid {
  const parsed = parseJsonRecord(content);
  if (typeof parsed === "string") {
    return parsed;
  }
  const root = parseRoot(parsed);
  if (typeof root === "string") {
    return root;
  }
  const variables = parseVariables(parsed["variables"]);
  return typeof variables === "string" ? variables : { version: 1, ...root, variables };
}

/** Loading and verifying `--config <file>` (default `maruhi.proxy.json`). */
export function loadProxyConfig(path: string): Effect.Effect<ProxyConfig, CliError> {
  return Effect.gen(function* () {
    const content = yield* Effect.tryPromise({
      try: () => readFile(path, "utf8"),
      catch: () =>
        cliError(
          `Cannot read the proxy config ${path}. Create it (see the Credential brokering page in the docs), or pass --config <file>`,
        ),
    });
    const parsed = parseProxyConfig(content);
    if (typeof parsed === "string") {
      return yield* Effect.fail(cliError(`The proxy config ${path} is invalid: ${parsed}`));
    }
    return parsed;
  });
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
): Effect.Effect<ProxyConfig | null, CliError> {
  return Effect.gen(function* () {
    const exists = yield* Effect.tryPromise({
      try: () => stat(path).then(() => true),
      catch: (error: unknown) => error,
    }).pipe(
      Effect.catch((error: unknown) =>
        (error as NodeJS.ErrnoException).code === "ENOENT"
          ? Effect.succeed(false)
          : Effect.fail(
              cliError(
                `Cannot read the proxy config ${path} (it exists but is not readable). Fix it, or run with --plain from a terminal to inject the values directly`,
              ),
            ),
      ),
    );
    return exists ? yield* loadProxyConfig(path) : null;
  });
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
