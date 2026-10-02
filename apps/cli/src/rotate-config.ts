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
import { dirname, isAbsolute, join, relative, sep } from "node:path";

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
import { isDeniedEnvName, SAFE_ENV_NAME } from "./run.ts";

/** Default location of the rotation config, relative to the working directory. */
export const DEFAULT_ROTATE_CONFIG_PATH = "maruhi.rotate.json";

/** The connectors (rotate-connector.ts implements them). */
type RotateConnectorKind =
  | "aws-iam-access-key"
  | "cloudflare-api-token"
  | "postgres"
  | "mysql"
  | "exec";

const ROTATE_CONNECTOR_KINDS: readonly RotateConnectorKind[] = [
  "aws-iam-access-key",
  "cloudflare-api-token",
  "postgres",
  "mysql",
  "exec",
];

/**
 * The prefix of the control variables the `exec` connector adds to a
 * script's environment (`MH_ROTATE_VARIABLE` / `_ENVIRONMENT` / `_PHASE` /
 * `_CURRENT` / `_PREVIOUS` — rotate-connector.ts). Outside the `MARUHI_`
 * namespace on purpose: that namespace never reaches a child
 * (run.ts's buildChildEnvironment), and nothing in maruhi reads these.
 * Input and companion names may not start with it.
 */
export const EXEC_CONTROL_PREFIX = "MH_ROTATE_";

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
    }
  | {
      /**
       * A script of the repository does the issuer's part (PF8 —
       * docs/notes/pf7-pf8-design.md §3): maruhi runs it with the current
       * credential and the admin inputs in its environment, reads the new
       * credential from its stdout, and runs the finalize script the same
       * way with the previous credential. maruhi interprets nothing about
       * the issuer, so the set of issuers is whatever the team can script.
       */
      readonly connector: "exec";
      /** The rotate script's argv (no shell — the first element is the executable, resolved from `cwd`). */
      readonly rotate: readonly string[];
      /**
       * The finalize script's argv. null = none: the rotate script is then
       * expected to retire the previous credential itself, so the rotation
       * has no grace period and asks for confirmation.
       */
      readonly finalize: readonly string[] | null;
      /** The scripts' working directory (absolute — the config's directory, or `cwd` joined onto it). */
      readonly cwd: string;
      /** What the rotate script prints: the new value alone, or a JSON object (companions, facts). */
      readonly output: "value" | "json";
      /** Environment variable name → the maruhi variable it carries (the credential's companions, pushed next to it). */
      readonly companions: Readonly<Record<string, string>>;
      /** Environment variable name → the maruhi variable supplying it (free-form names for this connector). */
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
  exec: ["connector", "rotate", "finalize", "cwd", "output", "companions", "inputs"],
};

/** The input names each connector takes (null = any environment variable name — the `exec` connector's scripts choose). */
const CONNECTOR_INPUTS: Readonly<Record<RotateConnectorKind, readonly string[] | null>> = {
  "aws-iam-access-key": ["accessKeyId", "secretAccessKey", "sessionToken"],
  "cloudflare-api-token": ["token"],
  postgres: ["adminUrl"],
  mysql: ["adminUrl"],
  exec: null,
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
  const refusedName = inputNamesRefusal(name, kind, raw);
  if (refusedName !== null) {
    return refusedName;
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

/**
 * The input names a rule may use: the connector's fixed set, or — for the
 * exec connector, whose inputs land in the script's environment under
 * their own names — any name the child can carry. null = acceptable.
 */
function inputNamesRefusal(
  name: string,
  kind: RotateConnectorKind,
  raw: Record<string, unknown>,
): Invalid | null {
  const allowed = CONNECTOR_INPUTS[kind];
  if (allowed !== null) {
    const unknown = unknownKeys(raw, allowed);
    return unknown.length === 0
      ? null
      : `variables.${name}.inputs has unknown keys (${unknown.join(", ")}); the ${kind} connector takes ${allowed.join(", ")}`;
  }
  for (const inputName of Object.keys(raw)) {
    const refused = scriptEnvNameRefusal(inputName);
    if (refused !== null) {
      return `variables.${name}.inputs.${inputName}: ${refused}`;
    }
  }
  return null;
}

/**
 * Why a name cannot be an environment variable of an `exec` script: not a
 * POSIX identifier, an execution-control name (run.ts's denylist — the
 * same line as `maruhi run`'s injection), or the connector's own control
 * namespace. null = acceptable.
 */
function scriptEnvNameRefusal(envName: string): Invalid | null {
  if (!SAFE_ENV_NAME.test(envName)) {
    return "must be an environment variable name (letters, digits, _, starting with a letter or _)";
  }
  if (isDeniedEnvName(envName)) {
    return "is an execution-control environment variable and cannot be set for a script (choose another name)";
  }
  if (envName.toUpperCase().startsWith(EXEC_CONTROL_PREFIX)) {
    return `starts with ${EXEC_CONTROL_PREFIX}, the prefix of the control variables maruhi sets for the script (choose another name)`;
  }
  return null;
}

/** Whether two names are the same environment variable where names are case-insensitive (the rule `maruhi run` applies to its own injection). */
function sameEnvName(a: string, b: string): boolean {
  return a.toUpperCase() === b.toUpperCase();
}

/** The first pair of names that differ only by case ("A and a"), or null. */
function duplicateEnvName(names: readonly string[]): string | null {
  const seen = new Map<string, string>();
  for (const candidate of names) {
    const upper = candidate.toUpperCase();
    const earlier = seen.get(upper);
    if (earlier !== undefined && earlier !== candidate) {
      return `${earlier} and ${candidate}`;
    }
    seen.set(upper, candidate);
  }
  return null;
}

/** A script's argv: a non-empty list of strings whose first element is the executable (a bare string = that executable alone, no word splitting). */
function parseArgv(path: string, raw: unknown): readonly string[] | Invalid {
  const list = typeof raw === "string" ? [raw] : raw;
  if (
    !Array.isArray(list) ||
    list.length === 0 ||
    !list.every((item) => typeof item === "string") ||
    (list[0] as string).trim().length === 0
  ) {
    return `${path} must be the script's command: a non-empty list of strings whose first element is the executable (or that executable as one string)`;
  }
  return list as readonly string[];
}

/** The scripts' working directory: the config's directory, or a relative path joined onto it (an absolute path would not travel with the repository). */
function parseCwd(
  name: string,
  raw: unknown,
  configDir: string,
): { readonly cwd: string } | Invalid {
  if (raw === undefined) {
    return { cwd: configDir };
  }
  if (typeof raw !== "string" || raw.length === 0 || isAbsolute(raw)) {
    return `variables.${name}.cwd must be a non-empty relative path (resolved from the rotation config's directory)`;
  }
  const cwd = join(configDir, raw);
  // The scripts travel with the repository that holds the config; a cwd
  // that climbs out of its directory would run whatever lives there
  const inside = relative(configDir, cwd);
  if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) {
    return `variables.${name}.cwd must stay inside the rotation config's directory (${raw} climbs out of it)`;
  }
  return { cwd };
}

function parseCompanions(
  name: string,
  raw: unknown,
  inputs: InputRefs,
): Readonly<Record<string, string>> | Invalid {
  if (raw === undefined) {
    return {};
  }
  if (!isRecord(raw)) {
    return `variables.${name}.companions must be an object (environment variable name → the maruhi variable it carries)`;
  }
  const companions: Record<string, string> = {};
  for (const [envName, variable] of Object.entries(raw)) {
    const refused = companionNameRefusal(
      name,
      envName,
      Object.keys(inputs),
      Object.keys(companions),
    );
    if (refused !== null) {
      return refused;
    }
    if (typeof variable !== "string" || !ENV_NAME.test(variable)) {
      return `variables.${name}.companions.${envName} must name the maruhi variable it carries (letters, digits, _)`;
    }
    if (variable === name) {
      return `variables.${name}.companions.${envName} must differ from the rule's own variable (the credential itself is injected under its name)`;
    }
    companions[envName] = variable;
  }
  return companions;
}

/**
 * Why a companion's environment variable name cannot be used: not a name a
 * script may carry, or a collision with the rule's own name, an input, or
 * an earlier companion. Collisions are judged case-insensitively: the
 * script may run where environment variable names are (run.ts's
 * injection rule). null = acceptable.
 */
function companionNameRefusal(
  name: string,
  envName: string,
  inputNames: readonly string[],
  earlier: readonly string[],
): Invalid | null {
  const refused = scriptEnvNameRefusal(envName);
  if (refused !== null) {
    return `variables.${name}.companions.${envName}: ${refused}`;
  }
  if (sameEnvName(envName, name)) {
    return `variables.${name}.companions.${envName} collides with the rule's own variable (the credential itself is injected under that name)`;
  }
  if (inputNames.some((inputName) => sameEnvName(inputName, envName))) {
    return `variables.${name}.companions.${envName} is also an input name (one environment variable cannot carry both)`;
  }
  if (earlier.some((seen) => sameEnvName(seen, envName))) {
    return `variables.${name}.companions.${envName} repeats another companion name (names differing only by case are one environment variable)`;
  }
  return null;
}

function parseExecRule(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
  configDir: string,
): RotateRule | Invalid {
  const rotate = parseArgv(`variables.${name}.rotate`, value["rotate"]);
  if (typeof rotate === "string") {
    return rotate;
  }
  const finalize =
    value["finalize"] === undefined || value["finalize"] === null
      ? null
      : parseArgv(`variables.${name}.finalize`, value["finalize"]);
  if (typeof finalize === "string") {
    return finalize;
  }
  const cwd = parseCwd(name, value["cwd"], configDir);
  if (typeof cwd === "string") {
    return cwd;
  }
  const names = execNamesRefusal(name, inputs);
  if (names !== null) {
    return names;
  }
  const answer = parseExecAnswer(name, value, inputs);
  if (typeof answer === "string") {
    return answer;
  }
  return { connector: "exec", rotate, finalize, cwd: cwd.cwd, ...answer, inputs };
}

/**
 * The exec rule's own name and its inputs as environment variable names:
 * the credential is injected under the rule's own variable name, so that
 * name must be one a script may carry (the same line as its inputs and
 * companions), and no input may collide with it — judged
 * case-insensitively (run.ts's injection rule). null = acceptable.
 */
function execNamesRefusal(name: string, inputs: InputRefs): Invalid | null {
  const ownName = scriptEnvNameRefusal(name);
  if (ownName !== null) {
    return `variables.${name}: the exec connector injects the credential under the variable's own name, which ${ownName}`;
  }
  const colliding = Object.keys(inputs).find((inputName) => sameEnvName(inputName, name));
  if (colliding !== undefined) {
    return `variables.${name}.inputs.${colliding} collides with the rule's own variable (the current credential is injected under that name)`;
  }
  const inputCase = duplicateEnvName(Object.keys(inputs));
  if (inputCase !== null) {
    return `variables.${name}.inputs has two names that differ only by case (${inputCase}); they are one environment variable`;
  }
  return null;
}

/** The exec rule's answer shape: `output` and the companions it may carry. */
function parseExecAnswer(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
):
  | { readonly output: "value" | "json"; readonly companions: Readonly<Record<string, string>> }
  | Invalid {
  const output = value["output"] ?? "value";
  if (output !== "value" && output !== "json") {
    return `variables.${name}.output must be "value" (the script prints the new value) or "json" (an object with value, companions, facts)`;
  }
  const companions = parseCompanions(name, value["companions"], inputs);
  if (typeof companions === "string") {
    return companions;
  }
  if (output === "value" && Object.keys(companions).length > 0) {
    return `variables.${name}.companions needs "output": "json" (only a JSON answer can carry companions)`;
  }
  return { output, companions };
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

function parseRule(name: string, value: unknown, configDir: string): RotateRule | Invalid {
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
    case "exec":
      return parseExecRule(name, value, inputs, configDir);
  }
}

/** The companion variables a rule's credential carries (companion name → the variable that holds it). */
export function companionVariablesOf(rule: RotateRule): Readonly<Record<string, string>> {
  switch (rule.connector) {
    case "aws-iam-access-key":
      return { accessKeyId: rule.accessKeyIdVariable };
    case "exec":
      return rule.companions;
    default:
      return {};
  }
}

/** What a rule calls its companion variable in a refusal (the AWS key id keeps its own wording). */
function companionNoun(rule: RotateRule): string {
  return rule.connector === "aws-iam-access-key" ? "the access key id" : "a companion";
}

/** Two rules naming one companion variable (the AWS wording when both are AWS rules). */
function sharedCompanionRefusal(
  variables: ReadonlyMap<string, RotateRule>,
  other: string,
  name: string,
  companion: string,
): Invalid {
  const bothAws =
    variables.get(other)?.connector === "aws-iam-access-key" &&
    variables.get(name)?.connector === "aws-iam-access-key";
  return `variables.${other} and variables.${name} name the same ${bothAws ? "access key id" : "companion"} variable (${companion})`;
}

/** A companion (the AWS key id, an exec rule's companions) belongs to exactly one rule and is not a rule itself. */
function companionConflict(variables: ReadonlyMap<string, RotateRule>): Invalid | null {
  const owners = new Map<string, string>();
  for (const [name, rule] of variables) {
    for (const companion of Object.values(companionVariablesOf(rule))) {
      if (variables.has(companion)) {
        return `variables.${companion} is ${companionNoun(rule)} of ${name} and cannot carry a rule of its own`;
      }
      const other = owners.get(companion);
      if (other === name) {
        return `variables.${name}.companions name the variable ${companion} twice`;
      }
      if (other !== undefined) {
        return sharedCompanionRefusal(variables, other, name, companion);
      }
      owners.set(companion, name);
    }
  }
  return null;
}

function parseVariables(
  raw: unknown,
  configDir: string,
): ReadonlyMap<string, RotateRule> | Invalid {
  if (!isRecord(raw)) {
    return "variables must be an object (variable name → rule); it may be empty";
  }
  const variables = new Map<string, RotateRule>();
  for (const [name, value] of Object.entries(raw)) {
    if (!ENV_NAME.test(name)) {
      return "variables keys must be variable names (letters, digits, _, starting with a letter or _)";
    }
    const rule = parseRule(name, value, configDir);
    if (typeof rule === "string") {
      return rule;
    }
    variables.set(name, rule);
  }
  return companionConflict(variables) ?? variables;
}

/**
 * Parses the rotation config. `configDir` is the directory the config was
 * read from — the base of an `exec` rule's working directory (the scripts
 * travel with the repository, so they are named relative to the config).
 */
export function parseRotateConfig(
  content: string,
  options: { readonly configDir?: string | undefined } = {},
): RotateConfig | Invalid {
  const parsed = parseJsonRecord(content);
  if (typeof parsed === "string") {
    return parsed;
  }
  const header = parseConfigHeader(parsed, ROOT_KEYS);
  if (typeof header === "string") {
    return header;
  }
  const variables = parseVariables(parsed["variables"], options.configDir ?? ".");
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
    const parsed = parseRotateConfig(content, { configDir: dirname(path) });
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
    if (Object.values(companionVariablesOf(rule)).includes(name)) {
      return { primary, rule };
    }
  }
  return null;
}

/** Matching the config's `project` against the resolved project (a mismatch is a config of another project). */
export function configNamesProject(config: RotateConfig, projectId: string): boolean {
  return config.projectId === undefined || config.projectId === projectId;
}
