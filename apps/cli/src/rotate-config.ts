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
//
// The JSON is described with Schema and decoded with
// `Schema.decodeUnknownResult`: the leaf shapes are real schema nodes
// (String / Literals / Record / Struct), and everything whose wording or
// ordering is conditional — the connector dispatch, the per-connector key
// sets, the cross-rule checks — is a `Schema.makeFilter` in the same
// sequence the hand-written checks ran (the first reason wins, like
// before). The filters report `Schema.FilterIssue`s: a `{path, issue}`
// whose issue starts with a separator is a suffix appended to the dotted
// path ("variables.X.connector" + " must be ..."), and a plain string is
// a complete reason; the wording is unchanged.

import { dirname, isAbsolute, join, relative, sep } from "node:path";

import { Effect, Result, Schema } from "effect";

import {
  configHeader,
  environmentId,
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
} from "./config-schema.ts";
import type { CliError } from "./errors.ts";
import { loadIfPresent, parseConfigHeader, unknownKeys } from "./json-record.ts";
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

// A database role / account name the connector can quote safely (no quotes,
// backslashes, whitespace, or control characters — names outside this set are
// refused rather than escaped: a rotation must never run a statement the
// author did not mean)
const DB_NAME = /^[A-Za-z0-9_.@-]{1,128}$/;
// An IAM user name (IAM's own character class)
const IAM_USER = /^[\w+=,.@-]{1,64}$/;
// A Cloudflare account id (32 hex digits)
const CF_ACCOUNT = /^[0-9a-f]{32}$/;

/** `inputs.<input>` in its object form: `{ environment, name }` pointing at another environment's variable. */
const INPUT_REF_RECORD = JsonRecord(
  " must be a variable name or an object with environment and name",
)
  .check(
    Schema.makeFilter(
      (record) =>
        unknownKeysRefusal(
          record,
          ["environment", "name"],
          "an input takes environment and name",
        ) ?? undefined,
    ),
  )
  .pipe(
    Schema.decodeTo(
      Schema.Struct({
        environment: environmentId(" must be an environment id").annotateKey({
          messageMissingKey: " must be an environment id",
        }),
        name: envNameLeaf(" must be a variable name (letters, digits, _)").annotateKey({
          messageMissingKey: " must be a variable name (letters, digits, _)",
        }),
      }),
    ),
  );

function parseInputRef(value: unknown): InputRef | Reason {
  // A bare string names a variable of the target's own environment
  if (typeof value === "string") {
    return SAFE_ENV_NAME.test(value)
      ? { environment: null, name: value }
      : " must name a variable (letters, digits, _)";
  }
  const decoded = Schema.decodeUnknownResult(INPUT_REF_RECORD)(value);
  return Result.isSuccess(decoded) ? decoded.success : decoded.failure.issue;
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

function parseInputs(name: string, kind: RotateConnectorKind, raw: unknown): InputRefs | Reason {
  if (raw === undefined) {
    return {};
  }
  const record = Schema.decodeUnknownResult(
    JsonRecord(" must be an object (input name → variable)"),
  )(raw);
  if (Result.isFailure(record)) {
    return { path: ["inputs"], issue: record.failure.issue };
  }
  const refusedName = inputNamesRefusal(name, kind, record.success);
  if (refusedName !== null) {
    return refusedName;
  }
  const inputs: Record<string, InputRef> = {};
  for (const [inputName, value] of Object.entries(record.success)) {
    const parsed = parseInputRef(value);
    if (isReason(parsed)) {
      return { path: ["inputs", inputName], issue: reasonIssue(parsed) };
    }
    inputs[inputName] = parsed;
  }
  const aws = kind === "aws-iam-access-key" ? awsInputsInvalid(name, inputs) : null;
  return aws ?? inputs;
}

/** `roles`: null / absent = in-place rotation; otherwise exactly two different role names. */
const ROLES = Schema.Unknown.check(
  Schema.makeFilter((raw) => {
    if (
      !Array.isArray(raw) ||
      raw.length !== 2 ||
      !raw.every((role) => typeof role === "string" && DB_NAME.test(role))
    ) {
      return " must be a list of exactly two role names (letters, digits, _ . @ -) alternated across rotations";
    }
    return raw[0] === raw[1] ? " must name two different roles" : undefined;
  }),
);

function parseRoles(raw: unknown): readonly [string, string] | null | Reason {
  if (raw === undefined || raw === null) {
    return null;
  }
  const decoded = Schema.decodeUnknownResult(ROLES)(raw);
  if (Result.isFailure(decoded)) {
    return { path: ["roles"], issue: decoded.failure.issue };
  }
  // The schema checked it is a two-entry list of DB_NAME strings
  return decoded.success as [string, string];
}

function parseAwsRule(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
): RotateRule | Reason {
  const idVariable = field(
    value,
    "accessKeyIdVariable",
    envNameLeaf(" must name the variable holding the matching access key id"),
  );
  if (isReason(idVariable)) {
    return idVariable;
  }
  if (idVariable.value === name) {
    return {
      path: ["accessKeyIdVariable"],
      issue:
        " must differ from the rule's own variable (the rule is keyed by the secret access key)",
    };
  }
  const user = field(
    value,
    "user",
    Schema.UndefinedOr(stringLeaf(" must be an IAM user name", (raw) => IAM_USER.test(raw))),
  );
  if (isReason(user)) {
    return user;
  }
  return {
    connector: "aws-iam-access-key",
    accessKeyIdVariable: idVariable.value,
    user: user.value ?? null,
    inputs,
  };
}

function parseCloudflareRule(
  value: Record<string, unknown>,
  inputs: InputRefs,
): RotateRule | Reason {
  const accountId = field(
    value,
    "accountId",
    Schema.UndefinedOr(
      stringLeaf(" must be a Cloudflare account id (32 hex digits)", (raw) => CF_ACCOUNT.test(raw)),
    ),
  );
  if (isReason(accountId)) {
    return accountId;
  }
  return { connector: "cloudflare-api-token", accountId: accountId.value ?? null, inputs };
}

function parseDbRule(
  kind: "postgres" | "mysql",
  value: Record<string, unknown>,
  inputs: InputRefs,
): RotateRule | Reason {
  const roles = parseRoles(value["roles"]);
  if (isReason(roles)) {
    return roles;
  }
  if (kind === "postgres") {
    return { connector: kind, roles, inputs };
  }
  const host = field(
    value,
    "host",
    Schema.NullishOr(
      stringLeaf(
        " must be the account's host part (default %)",
        (raw) => raw.length > 0 && raw.length <= 255 && !/['\\\s]/.test(raw),
      ),
    ),
  );
  if (isReason(host)) {
    return host;
  }
  return { connector: kind, roles, host: host.value ?? "%", inputs };
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
const ARGV = Schema.Unknown.check(
  Schema.makeFilter((raw) => {
    const list = typeof raw === "string" ? [raw] : raw;
    return Array.isArray(list) &&
      list.length > 0 &&
      list.every((item) => typeof item === "string") &&
      (list[0] as string).trim().length > 0
      ? undefined
      : " must be the script's command: a non-empty list of strings whose first element is the executable (or that executable as one string)";
  }),
);

function parseArgv(raw: unknown): readonly string[] | Reason {
  const decoded = Schema.decodeUnknownResult(ARGV)(raw);
  if (Result.isFailure(decoded)) {
    return decoded.failure.issue;
  }
  // The schema checked the shape (a bare string is the executable alone)
  const list = typeof raw === "string" ? [raw] : raw;
  return list as readonly string[];
}

/** The scripts' working directory: the config's directory, or a relative path joined onto it (an absolute path would not travel with the repository). */
function parseCwd(raw: unknown, configDir: string): { readonly cwd: string } | Reason {
  if (raw === undefined) {
    return { cwd: configDir };
  }
  const relativePath = Schema.decodeUnknownResult(
    stringLeaf(
      " must be a non-empty relative path (resolved from the rotation config's directory)",
      (value) => value.length > 0 && !isAbsolute(value),
    ),
  )(raw);
  if (Result.isFailure(relativePath)) {
    return { path: ["cwd"], issue: relativePath.failure.issue };
  }
  const cwd = join(configDir, relativePath.success);
  // The scripts travel with the repository that holds the config; a cwd
  // that climbs out of its directory would run whatever lives there
  const inside = relative(configDir, cwd);
  if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) {
    return {
      path: ["cwd"],
      issue: ` must stay inside the rotation config's directory (${relativePath.success} climbs out of it)`,
    };
  }
  return { cwd };
}

function parseCompanions(
  name: string,
  raw: unknown,
  inputs: InputRefs,
): Readonly<Record<string, string>> | Reason {
  if (raw === undefined) {
    return {};
  }
  const record = Schema.decodeUnknownResult(
    JsonRecord(" must be an object (environment variable name → the maruhi variable it carries)"),
  )(raw);
  if (Result.isFailure(record)) {
    return { path: ["companions"], issue: record.failure.issue };
  }
  const companions: Record<string, string> = {};
  for (const [envName, variable] of Object.entries(record.success)) {
    const refused = companionNameRefusal(
      name,
      envName,
      Object.keys(inputs),
      Object.keys(companions),
    );
    if (refused !== null) {
      return refused;
    }
    const parsed = Schema.decodeUnknownResult(
      envNameLeaf(" must name the maruhi variable it carries (letters, digits, _)"),
    )(variable);
    if (Result.isFailure(parsed)) {
      return { path: ["companions", envName], issue: parsed.failure.issue };
    }
    if (parsed.success === name) {
      return {
        path: ["companions", envName],
        issue:
          " must differ from the rule's own variable (the credential itself is injected under its name)",
      };
    }
    companions[envName] = parsed.success;
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

/** The exec rule's own name and its inputs as environment variable names: the credential is injected under the rule's own variable name, so that name must be one a script may carry (the same line as its inputs and companions), and no input may collide with it — judged case-insensitively (run.ts's injection rule). null = acceptable. */
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
  | Reason {
  const output = field(
    value,
    "output",
    Schema.NullishOr(
      Schema.Literals(["value", "json"]).annotate({
        message:
          ' must be "value" (the script prints the new value) or "json" (an object with value, companions, facts)',
      }),
    ),
  );
  if (isReason(output)) {
    return output;
  }
  const companions = parseCompanions(name, value["companions"], inputs);
  if (isReason(companions)) {
    return companions;
  }
  const resolved = output.value ?? "value";
  if (resolved === "value" && Object.keys(companions).length > 0) {
    return {
      path: ["companions"],
      issue: ' needs "output": "json" (only a JSON answer can carry companions)',
    };
  }
  return { output: resolved, companions };
}

function parseExecRule(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
  configDir: string,
): RotateRule | Reason {
  const rotate = parseArgv(value["rotate"]);
  if (isReason(rotate)) {
    return { path: ["rotate"], issue: reasonIssue(rotate) };
  }
  const finalize =
    value["finalize"] === undefined || value["finalize"] === null
      ? null
      : parseArgv(value["finalize"]);
  if (isReason(finalize)) {
    return { path: ["finalize"], issue: reasonIssue(finalize) };
  }
  const cwd = parseCwd(value["cwd"], configDir);
  if (isReason(cwd)) {
    return cwd;
  }
  const names = execNamesRefusal(name, inputs);
  if (names !== null) {
    return names;
  }
  const answer = parseExecAnswer(name, value, inputs);
  if (isReason(answer)) {
    return answer;
  }
  return { connector: "exec", rotate, finalize, cwd: cwd.cwd, ...answer, inputs };
}

/** The rule's connector kind and the key check (the shape every rule shares). */
function parseRuleHead(
  value: Record<string, unknown>,
): { readonly kind: RotateConnectorKind } | Reason {
  const connector = field(
    value,
    "connector",
    Schema.Literals(ROTATE_CONNECTOR_KINDS).annotate({
      message: ` must be one of ${ROTATE_CONNECTOR_KINDS.join(", ")}`,
    }),
  );
  if (isReason(connector)) {
    return connector;
  }
  const unknown = unknownKeysRefusal(
    value,
    RULE_KEYS[connector.value],
    `a ${connector.value} rule accepts ${RULE_KEYS[connector.value].join(", ")}`,
  );
  return unknown === undefined ? { kind: connector.value } : unknown;
}

function parseRule(name: string, value: unknown, configDir: string): RotateRule | Reason {
  const record = Schema.decodeUnknownResult(JsonRecord(" must be an object with a connector"))(
    value,
  );
  if (Result.isFailure(record)) {
    return record.failure.issue;
  }
  const head = parseRuleHead(record.success);
  if (isReason(head)) {
    return head;
  }
  const { kind } = head;
  const inputs = parseInputs(name, kind, record.success["inputs"]);
  if (isReason(inputs)) {
    return inputs;
  }
  switch (kind) {
    case "aws-iam-access-key":
      return parseAwsRule(name, record.success, inputs);
    case "cloudflare-api-token":
      return parseCloudflareRule(record.success, inputs);
    case "postgres":
    case "mysql":
      return parseDbRule(kind, record.success, inputs);
    case "exec":
      return parseExecRule(name, record.success, inputs, configDir);
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

/** The `variables` object: every rule, then the companion-conflict check across them. */
function parseVariables(raw: unknown, configDir: string): ReadonlyMap<string, RotateRule> | Reason {
  const record = Schema.decodeUnknownResult(
    JsonRecord(" must be an object (variable name → rule); it may be empty"),
  )(raw);
  if (Result.isFailure(record)) {
    return record.failure.issue;
  }
  const variables = new Map<string, RotateRule>();
  for (const [name, value] of Object.entries(record.success)) {
    if (!SAFE_ENV_NAME.test(name)) {
      return "variables keys must be variable names (letters, digits, _, starting with a letter or _)";
    }
    const rule = parseRule(name, value, configDir);
    if (isReason(rule)) {
      return { path: [name], issue: reasonIssue(rule) };
    }
    variables.set(name, rule);
  }
  return companionConflict(variables) ?? variables;
}

/**
 * The document as a Schema: a JSON object, then the header fields, then
 * the rules — the same order the reasons ran in before (the first one
 * wins). `parseConfigHeader` (json-record.ts) stays the header's check —
 * it returns the reason's string, a verbatim filter issue.
 */
const RotateDocument = (configDir: string) =>
  JsonRecord("the top level must be an object")
    .check(configHeader(ROOT_KEYS))
    .check(
      Schema.makeFilter((record) => {
        const variables = parseVariables(record["variables"], configDir);
        return isReason(variables)
          ? { path: ["variables"], issue: reasonIssue(variables) }
          : undefined;
      }),
    );

/**
 * Parses the rotation config. `configDir` is the directory the config was
 * read from — the base of an `exec` rule's working directory (the scripts
 * travel with the repository, so they are named relative to the config).
 */
export function parseRotateConfig(
  content: string,
  options: { readonly configDir?: string | undefined } = {},
): RotateConfig | Invalid {
  const configDir = options.configDir ?? ".";
  const json = Schema.decodeUnknownResult(Schema.fromJsonString(Schema.Unknown))(content);
  if (Result.isFailure(json)) {
    return "not valid JSON";
  }
  const decoded = Schema.decodeUnknownResult(RotateDocument(configDir))(json.success);
  if (Result.isFailure(decoded)) {
    return issueReason(decoded.failure.issue);
  }
  // The document's filters already ran the same pure steps — re-running
  // them on the validated record cannot produce a reason
  const parsed = parseRotateConfigDocument(decoded.success, configDir);
  if (isReason(parsed)) {
    throw new Error("rotate-config: the document passed validation but failed to build");
  }
  return parsed;
}

/** The fused validation + build pass over a validated record (its checks are the document's filters). */
function parseRotateConfigDocument(
  record: Record<string, unknown>,
  configDir: string,
): RotateConfig | Reason {
  const header = parseConfigHeader(record, ROOT_KEYS);
  if (typeof header === "string") {
    return header;
  }
  const variables = parseVariables(record["variables"], configDir);
  return isReason(variables) ? variables : { version: 1, projectId: header.projectId, variables };
}

/** Loading and verifying `--config <file>` (default `maruhi.rotate.json`). */
export function loadRotateConfig(path: string): Effect.Effect<RotateConfig, CliError> {
  return loadConfig(
    path,
    "rotation config",
    "Create it (see the Rotation page in the docs), or pass --rotate-config <file>",
    (content) => parseRotateConfig(content, { configDir: dirname(path) }),
  ).pipe(Effect.map(({ parsed }) => parsed));
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
