import { type ProjectId } from "@maruhi/core";
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

export const DEFAULT_PROXY_CONFIG_PATH = "maruhi.proxy.json";

export type Surface = "header" | "path" | "query" | "body";

const SURFACES: readonly Surface[] = ["header", "path", "query", "body"];

const DEFAULT_SURFACES: readonly Surface[] = ["header"];

export interface HostPattern {
  readonly scheme: "https" | "http";
  readonly host: string;
  readonly wildcard: boolean;
  readonly port: number;
}

export type ConnectorKind = "github-app";

const CONNECTOR_KINDS: readonly ConnectorKind[] = ["github-app"];

export interface BrokerSettings {
  readonly hosts: readonly HostPattern[];
  readonly surfaces: readonly Surface[];
  readonly placeholder: string | undefined;
}

export type VariableRule =
  | ({ readonly mode: "broker" } & BrokerSettings)
  | ({
      readonly mode: "connector";
      readonly connector: ConnectorKind;
      readonly inputs: Readonly<Record<string, string>>;
    } & BrokerSettings)
  | { readonly mode: "passthrough" }
  | { readonly mode: "withhold" };

export interface ProxyConfig {
  readonly version: 1;
  readonly projectId: ProjectId | undefined;
  readonly unmatched: "allow" | "block";
  readonly unlisted: "withhold" | "passthrough";
  readonly variables: ReadonlyMap<string, VariableRule>;
}

const ROOT_KEYS = ["version", "project", "unmatched", "unlisted", "variables"] as const;
const BROKER_KEYS = ["mode", "hosts", "surfaces", "placeholder"] as const;
const CONNECTOR_KEYS = ["mode", "connector", "inputs", "hosts", "surfaces", "placeholder"] as const;
const BARE_KEYS = ["mode"] as const;

const CONNECTOR_INPUTS: Readonly<Record<ConnectorKind, readonly string[]>> = {
  "github-app": ["appId", "privateKey", "installationId"],
};

const HOST_NAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;
const PLACEHOLDER = /^[\x21-\x7E]{16,256}$/;

function isLoopbackHost(host: string, wildcard: boolean): boolean {
  if (host === "localhost" || host.endsWith(".localhost")) {
    return true;
  }
  return !wildcard && /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

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
  if (wildcard && !rest.includes(".") && rest !== "localhost") {
    return "a wildcard needs at least two labels after `*.` (for example `*.example.com`; `*.localhost` is the exception)";
  }
  if (scheme === "http" && !isLoopbackHost(rest, wildcard)) {
    return "plain http:// is accepted only for loopback hosts (localhost, *.localhost, 127.0.0.0/8); a value toward any other host must travel over https";
  }
  return { scheme, host: rest, wildcard, port };
}

const HOSTS_MESSAGE = " must be a non-empty array of host entries";
const HOSTS = Schema.Array(Schema.Unknown)
  .annotate({ message: HOSTS_MESSAGE })
  .check(Schema.isMinLength(1, { message: HOSTS_MESSAGE }));

const HOST_ENTRY = Schema.String.annotate({
  message: " entries must be strings (host[:port], optionally with http:// or https://)",
});

const SURFACES_MESSAGE = ` must be a non-empty array of ${SURFACES.join(" | ")}`;
const SURFACES_FIELD = undefinedOr(
  SURFACES_MESSAGE,
  Schema.Array(
    Schema.Literals(SURFACES).annotate({ message: ` accepts only ${SURFACES.join(" | ")}` }),
  )
    .annotate({ message: SURFACES_MESSAGE })
    .check(Schema.isMinLength(1, { message: SURFACES_MESSAGE })),
);

const PLACEHOLDER_MESSAGE = " must be 16 to 256 printable ASCII characters without spaces";
const PLACEHOLDER_FIELD = undefinedOr(
  PLACEHOLDER_MESSAGE,
  stringLeaf(PLACEHOLDER_MESSAGE, (value) => PLACEHOLDER.test(value)),
);

const MODE = Schema.Literals(["broker", "connector", "passthrough", "withhold"]).annotate({
  message: " must be broker, connector, passthrough, or withhold",
});

const CONNECTOR = Schema.Literals(CONNECTOR_KINDS).annotate({
  message: ` must be one of ${CONNECTOR_KINDS.join(", ")}`,
});

const INPUT_VARIABLE = envNameLeaf(" must name a maruhi variable (letters, digits, _)");

function parseHosts(record: Record<string, unknown>): Parsed<readonly HostPattern[]> {
  return Result.gen(function* () {
    const entries = yield* field(record, "hosts", HOSTS);
    const hosts: HostPattern[] = [];
    for (const entry of entries) {
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

function registerRule(
  name: string,
  rule: VariableRule,
  placeholders: Set<string>,
  consumed: Map<string, string>,
): Parsed<void> {
  if ((rule.mode === "broker" || rule.mode === "connector") && rule.placeholder !== undefined) {
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

export function parseProxyConfig(content: string): ProxyConfig | Invalid {
  return parseConfigDocument(content, parseProxyDocument);
}

export interface LoadedProxyConfig {
  readonly config: ProxyConfig;
  readonly content: string;
}

export function loadProxyConfig(path: string): Effect.Effect<LoadedProxyConfig, CliError> {
  return loadConfig(
    path,
    "proxy config",
    "Create it (see the Credential brokering page in the docs), or pass --config <file>",
    parseProxyConfig,
  ).pipe(Effect.map(({ parsed, content }) => ({ config: parsed, content })));
}

export function loadProxyConfigIfPresent(
  path: string,
): Effect.Effect<LoadedProxyConfig | null, CliError> {
  return loadIfPresent(
    path,
    loadProxyConfig,
    `Cannot read the proxy config ${path} (it exists but is not readable). Fix it, or run with --plain from a terminal to inject the values directly`,
  );
}

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
