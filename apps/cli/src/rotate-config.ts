// The repository rotation config of `maruhi var rotate` (PF6 — ROADMAP
// "minimal upstream rotation" R2; docs/notes/pf6-design.md ruling R1).
//
// "Which variable is rotated by which connector, with which admin
// credential" is not a secret — it is a config versioned with the code,
// the same treatment as `maruhi.sync.json` (sync-config.ts) and
// `maruhi.proxy.json` (proxy-config.ts), within the "non-secret
// configuration" the CLI may persist (CLAUDE.md). No credential is held:
// an admin credential is **pointed at** as a normal maruhi variable (the
// same environment by default, or another one the member can decrypt —
// the ops environment that holds the issuer's admin credential). When no
// admin input is named, the credential rotates **itself** (the IAM user
// manages its own keys; the Cloudflare token carries API Tokens Write;
// the database role may change its own password).
//
// The format: a single JSON file (default `maruhi.rotate.json`, overridable
// with `--rotate-config`; `--config` is the sync config on `var rotate`). A version field, a `project` check, and unknown keys
// refused (a typo is never silently ignored — the sync / proxy discipline).
// The validation's wording says "which key and why" and never shows the
// value that was typed.
//
// Hosts are never configurable: each connector talks to its issuer's fixed
// API host (sync-http.ts's "no door for config to swap the host").

import { readFile } from "node:fs/promises";

import { isEnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import {
  isRecord,
  loadIfPresent,
  parseConfigHeader,
  parseJsonRecord,
  unknownKeys,
} from "./json-record.ts";

/** Default location of the rotation config, relative to the working directory. */
export const DEFAULT_ROTATE_CONFIG_PATH = "maruhi.rotate.json";

/** The connectors (rotate-connector.ts implements them). */
type RotateConnectorKind = "aws-iam-access-key" | "cloudflare-api-token" | "postgres" | "mysql";

const ROTATE_CONNECTOR_KINDS: readonly RotateConnectorKind[] = [
  "aws-iam-access-key",
  "cloudflare-api-token",
  "postgres",
  "mysql",
];

/** Where an admin input lives: a variable of the target's environment (`environment` null) or of another one. */
export interface InputRef {
  readonly environment: string | null;
  readonly name: string;
}

/** The admin inputs a connector consumes (input name → the variable that supplies it). Empty = self-rotation. */
export type InputRefs = Readonly<Record<string, InputRef>>;

/** The per-variable rule (the discriminant is the connector). */
export type RotateRule =
  | {
      readonly connector: "aws-iam-access-key";
      /** The variable holding the access key id that pairs with the secret this rule is keyed by. */
      readonly accessKeyIdVariable: string;
      /** The IAM user name (optional — derived from the current key at the issuer when absent). */
      readonly user: string | null;
      readonly inputs: InputRefs;
    }
  | {
      readonly connector: "cloudflare-api-token";
      /** An account-owned token's account id (null = a user-owned token). */
      readonly accountId: string | null;
      readonly inputs: InputRefs;
    }
  | {
      readonly connector: "postgres";
      /** Two roles alternated across rotations (null = the URL's role changes its own password in place). */
      readonly roles: readonly [string, string] | null;
      readonly inputs: InputRefs;
    }
  | {
      readonly connector: "mysql";
      readonly roles: readonly [string, string] | null;
      /** The account's host part (`'user'@'host'` — default `%`). */
      readonly host: string;
      readonly inputs: InputRefs;
    };

export interface RotateConfig {
  readonly version: 1;
  /** The project the config belongs to (optional; checked against the resolved project when present). */
  readonly projectId: string | undefined;
  /** Variable name → rule. */
  readonly variables: ReadonlyMap<string, RotateRule>;
}

type Invalid = string;

const ROOT_KEYS = ["version", "project", "variables"] as const;

/** The keys each connector's rule accepts, and the inputs it takes. */
const RULE_KEYS: Readonly<Record<RotateConnectorKind, readonly string[]>> = {
  "aws-iam-access-key": ["connector", "accessKeyIdVariable", "user", "inputs"],
  "cloudflare-api-token": ["connector", "accountId", "inputs"],
  postgres: ["connector", "roles", "inputs"],
  mysql: ["connector", "roles", "host", "inputs"],
};

const CONNECTOR_INPUTS: Readonly<Record<RotateConnectorKind, readonly string[]>> = {
  "aws-iam-access-key": ["accessKeyId", "secretAccessKey", "sessionToken"],
  "cloudflare-api-token": ["token"],
  postgres: ["adminUrl"],
  mysql: ["adminUrl"],
};

// An environment variable name (run.ts's SAFE_ENV_NAME — a POSIX identifier)
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
// A database role / account name the connector can quote safely (no quotes,
// backslashes, whitespace, or control characters — names outside this set are
// refused rather than escaped: a rotation must never run a statement the
// author did not mean)
const DB_NAME = /^[A-Za-z0-9_.@-]{1,128}$/;
// An IAM user name (IAM's own character class)
const IAM_USER = /^[\w+=,.@-]{1,64}$/;
// A Cloudflare account id (32 hex digits)
const CF_ACCOUNT = /^[0-9a-f]{32}$/;

function parseInputRef(name: string, inputName: string, value: unknown): InputRef | Invalid {
  if (typeof value === "string") {
    return ENV_NAME.test(value)
      ? { environment: null, name: value }
      : `variables.${name}.inputs.${inputName} must name a variable (letters, digits, _)`;
  }
  if (!isRecord(value)) {
    return `variables.${name}.inputs.${inputName} must be a variable name or an object with environment and name`;
  }
  const unknown = unknownKeys(value, ["environment", "name"]);
  if (unknown.length > 0) {
    return `variables.${name}.inputs.${inputName} has unknown keys (${unknown.join(", ")}); an input takes environment and name`;
  }
  const environment = value["environment"];
  const variable = value["name"];
  if (typeof environment !== "string" || !isEnvironmentId(environment)) {
    return `variables.${name}.inputs.${inputName}.environment must be an environment id`;
  }
  if (typeof variable !== "string" || !ENV_NAME.test(variable)) {
    return `variables.${name}.inputs.${inputName}.name must be a variable name (letters, digits, _)`;
  }
  return { environment, name: variable };
}

/** The AWS admin pair is consumed as a set: both keys, or neither (self-rotation); a session token rides only with the pair. */
function awsInputsInvalid(
  name: string,
  inputs: Readonly<Record<string, InputRef>>,
): Invalid | null {
  const hasId = "accessKeyId" in inputs;
  const hasSecret = "secretAccessKey" in inputs;
  if (hasId !== hasSecret) {
    return `variables.${name}.inputs must name both accessKeyId and secretAccessKey (an admin key pair), or neither (the key rotates itself)`;
  }
  if (!hasId && "sessionToken" in inputs) {
    return `variables.${name}.inputs.sessionToken needs accessKeyId and secretAccessKey alongside it`;
  }
  return null;
}

function parseInputs(name: string, kind: RotateConnectorKind, raw: unknown): InputRefs | Invalid {
  if (raw === undefined) {
    return {};
  }
  if (!isRecord(raw)) {
    return `variables.${name}.inputs must be an object (input name → variable)`;
  }
  const allowed = CONNECTOR_INPUTS[kind];
  const unknown = unknownKeys(raw, allowed);
  if (unknown.length > 0) {
    return `variables.${name}.inputs has unknown keys (${unknown.join(", ")}); the ${kind} connector takes ${allowed.join(", ")}`;
  }
  const inputs: Record<string, InputRef> = {};
  for (const [inputName, value] of Object.entries(raw)) {
    const parsed = parseInputRef(name, inputName, value);
    if (typeof parsed === "string") {
      return parsed;
    }
    inputs[inputName] = parsed;
  }
  const aws = kind === "aws-iam-access-key" ? awsInputsInvalid(name, inputs) : null;
  return aws ?? inputs;
}

function parseRoles(name: string, raw: unknown): readonly [string, string] | null | Invalid {
  if (raw === undefined || raw === null) {
    return null;
  }
  if (
    !Array.isArray(raw) ||
    raw.length !== 2 ||
    !raw.every((role) => typeof role === "string" && DB_NAME.test(role))
  ) {
    return `variables.${name}.roles must be a list of exactly two role names (letters, digits, _ . @ -) alternated across rotations`;
  }
  const [first, second] = raw as [string, string];
  if (first === second) {
    return `variables.${name}.roles must name two different roles`;
  }
  return [first, second];
}

function parseAwsRule(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
): RotateRule | Invalid {
  const idVariable = value["accessKeyIdVariable"];
  if (typeof idVariable !== "string" || !ENV_NAME.test(idVariable)) {
    return `variables.${name}.accessKeyIdVariable must name the variable holding the matching access key id`;
  }
  if (idVariable === name) {
    return `variables.${name}.accessKeyIdVariable must differ from the rule's own variable (the rule is keyed by the secret access key)`;
  }
  const user = value["user"];
  if (user !== undefined && (typeof user !== "string" || !IAM_USER.test(user))) {
    return `variables.${name}.user must be an IAM user name`;
  }
  return {
    connector: "aws-iam-access-key",
    accessKeyIdVariable: idVariable,
    user: user ?? null,
    inputs,
  };
}

function parseCloudflareRule(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
): RotateRule | Invalid {
  const accountId = value["accountId"];
  if (accountId !== undefined && (typeof accountId !== "string" || !CF_ACCOUNT.test(accountId))) {
    return `variables.${name}.accountId must be a Cloudflare account id (32 hex digits)`;
  }
  return { connector: "cloudflare-api-token", accountId: accountId ?? null, inputs };
}

function parseDbRule(
  name: string,
  kind: "postgres" | "mysql",
  value: Record<string, unknown>,
  inputs: InputRefs,
): RotateRule | Invalid {
  const roles = parseRoles(name, value["roles"]);
  if (typeof roles === "string") {
    return roles;
  }
  if (kind === "postgres") {
    return { connector: kind, roles, inputs };
  }
  const host = value["host"] ?? "%";
  if (typeof host !== "string" || host.length === 0 || host.length > 255 || /['\\\s]/.test(host)) {
    return `variables.${name}.host must be the account's host part (default %)`;
  }
  return { connector: kind, roles, host, inputs };
}

/** The rule's connector kind and the key check (the shape every rule shares). */
function parseRuleHead(
  name: string,
  value: Record<string, unknown>,
): { readonly kind: RotateConnectorKind } | Invalid {
  const connector = value["connector"];
  if (
    typeof connector !== "string" ||
    !(ROTATE_CONNECTOR_KINDS as readonly string[]).includes(connector)
  ) {
    return `variables.${name}.connector must be one of ${ROTATE_CONNECTOR_KINDS.join(", ")}`;
  }
  const kind = connector as RotateConnectorKind;
  const unknown = unknownKeys(value, RULE_KEYS[kind]);
  if (unknown.length > 0) {
    return `variables.${name} has unknown keys (${unknown.join(", ")}); a ${kind} rule accepts ${RULE_KEYS[kind].join(", ")}`;
  }
  return { kind };
}

function parseRule(name: string, value: unknown): RotateRule | Invalid {
  if (!isRecord(value)) {
    return `variables.${name} must be an object with a connector`;
  }
  const head = parseRuleHead(name, value);
  if (typeof head === "string") {
    return head;
  }
  const { kind } = head;
  const inputs = parseInputs(name, kind, value["inputs"]);
  if (typeof inputs === "string") {
    return inputs;
  }
  switch (kind) {
    case "aws-iam-access-key":
      return parseAwsRule(name, value, inputs);
    case "cloudflare-api-token":
      return parseCloudflareRule(name, value, inputs);
    case "postgres":
    case "mysql":
      return parseDbRule(name, kind, value, inputs);
  }
}

/** A companion (the AWS key id) belongs to exactly one rule and is not a rule itself. */
function companionConflict(variables: ReadonlyMap<string, RotateRule>): Invalid | null {
  const owners = new Map<string, string>();
  for (const [name, rule] of variables) {
    if (rule.connector !== "aws-iam-access-key") {
      continue;
    }
    if (variables.has(rule.accessKeyIdVariable)) {
      return `variables.${rule.accessKeyIdVariable} is the access key id of ${name} and cannot carry a rule of its own`;
    }
    const other = owners.get(rule.accessKeyIdVariable);
    if (other !== undefined) {
      return `variables.${other} and variables.${name} name the same access key id variable (${rule.accessKeyIdVariable})`;
    }
    owners.set(rule.accessKeyIdVariable, name);
  }
  return null;
}

function parseVariables(raw: unknown): ReadonlyMap<string, RotateRule> | Invalid {
  if (!isRecord(raw)) {
    return "variables must be an object (variable name → rule); it may be empty";
  }
  const variables = new Map<string, RotateRule>();
  for (const [name, value] of Object.entries(raw)) {
    if (!ENV_NAME.test(name)) {
      return "variables keys must be variable names (letters, digits, _, starting with a letter or _)";
    }
    const rule = parseRule(name, value);
    if (typeof rule === "string") {
      return rule;
    }
    variables.set(name, rule);
  }
  return companionConflict(variables) ?? variables;
}

export function parseRotateConfig(content: string): RotateConfig | Invalid {
  const parsed = parseJsonRecord(content);
  if (typeof parsed === "string") {
    return parsed;
  }
  const header = parseConfigHeader(parsed, ROOT_KEYS);
  if (typeof header === "string") {
    return header;
  }
  const variables = parseVariables(parsed["variables"]);
  return typeof variables === "string"
    ? variables
    : { version: 1, projectId: header.projectId, variables };
}

/** Loading and verifying `--config <file>` (default `maruhi.rotate.json`). */
export function loadRotateConfig(path: string): Effect.Effect<RotateConfig, CliError> {
  return Effect.gen(function* () {
    const content = yield* Effect.tryPromise({
      try: () => readFile(path, "utf8"),
      catch: () =>
        cliError(
          `Cannot read the rotation config ${path}. Create it (see the Rotation page in the docs), or pass --rotate-config <file>`,
        ),
    });
    const parsed = parseRotateConfig(content);
    if (typeof parsed === "string") {
      return yield* Effect.fail(cliError(`The rotation config ${path} is invalid: ${parsed}`));
    }
    return parsed;
  });
}

/** The default config when it exists in the working directory: null when absent; a broken one is reported, never skipped. */
export function loadRotateConfigIfPresent(
  path: string,
): Effect.Effect<RotateConfig | null, CliError> {
  return loadIfPresent(
    path,
    loadRotateConfig,
    `Cannot read the rotation config ${path} (it exists but is not readable). Fix it, or remove it`,
  );
}

/** The rule that covers a variable: by its own name, or as the access key id companion of an AWS rule. */
export interface ResolvedRule {
  /** The variable the rule is keyed by (the secret access key for AWS). */
  readonly primary: string;
  readonly rule: RotateRule;
}

export function ruleFor(config: RotateConfig, name: string): ResolvedRule | null {
  const own = config.variables.get(name);
  if (own !== undefined) {
    return { primary: name, rule: own };
  }
  for (const [primary, rule] of config.variables) {
    if (rule.connector === "aws-iam-access-key" && rule.accessKeyIdVariable === name) {
      return { primary, rule };
    }
  }
  return null;
}

/** Matching the config's `project` against the resolved project (a mismatch is a config of another project). */
export function configNamesProject(config: RotateConfig, projectId: string): boolean {
  return config.projectId === undefined || config.projectId === projectId;
}
