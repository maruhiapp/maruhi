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
// The JSON is read in one pass of steps over Schema-decoded leaves
// (String / Literals / Record / Array / Struct), in the sequence the
// hand-written checks ran (the first reason wins, like before);
// config-schema.ts renders the failing issue as the same path-and-reason
// wording.

import { dirname, isAbsolute, join, relative, sep } from "node:path";

import { type ProjectId } from "@maruhi/core";
import { Effect, Result, Schema } from "effect";

import {
  at,
  closedRecord,
  configHeader,
  decode,
  environmentId,
  envNameLeaf,
  field,
  type Invalid,
  knownKeys,
  loadConfig,
  nullishOr,
  objectLeaf,
  type Parsed,
  parseConfigDocument,
  refusal,
  refuse,
  stringLeaf,
  undefinedOr,
} from "./config-schema.ts";
import type { CliError } from "./errors.ts";
import { loadIfPresent, unknownKeys } from "./json-record.ts";
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
  readonly projectId: ProjectId | undefined;
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
const INPUT_REF_RECORD = closedRecord(
  " must be a variable name or an object with environment and name",
  ["environment", "name"],
  "an input takes environment and name",
).pipe(
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

function parseInputRef(value: unknown): Parsed<InputRef> {
  // A bare string names a variable of the target's own environment
  if (typeof value === "string") {
    return SAFE_ENV_NAME.test(value)
      ? Result.succeed({ environment: null, name: value })
      : refuse(" must name a variable (letters, digits, _)");
  }
  return decode(INPUT_REF_RECORD, value);
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

const INPUTS_MESSAGE = " must be an object (input name → variable)";
const INPUTS = undefinedOr(INPUTS_MESSAGE, objectLeaf(INPUTS_MESSAGE));

function parseInputs(
  name: string,
  kind: RotateConnectorKind,
  value: Record<string, unknown>,
): Parsed<InputRefs> {
  return Result.gen(function* () {
    const raw = yield* field(value, "inputs", INPUTS);
    if (raw === undefined) {
      return {};
    }
    yield* refusal(inputNamesRefusal(name, kind, raw));
    const inputs: Record<string, InputRef> = {};
    for (const [inputName, given] of Object.entries(raw)) {
      inputs[inputName] = yield* at(["inputs", inputName], parseInputRef(given));
    }
    yield* refusal(kind === "aws-iam-access-key" ? awsInputsInvalid(name, inputs) : null);
    return inputs;
  });
}

/** `roles`: exactly two role names (null / absent = in-place rotation). */
const DB_ROLE = Schema.String.check(Schema.isPattern(DB_NAME));
const ROLES = Schema.Tuple([DB_ROLE, DB_ROLE]);

function parseRoles(value: Record<string, unknown>): Parsed<readonly [string, string] | null> {
  const raw = value["roles"];
  if (raw === undefined || raw === null) {
    return Result.succeed(null);
  }
  // Every way the list can be wrong (not a list, a length other than two,
  // an entry that is not a role name) reads as the one reason
  const roles = Result.orElse(decode(ROLES, raw), () =>
    refuse(
      " must be a list of exactly two role names (letters, digits, _ . @ -) alternated across rotations",
    ),
  );
  return at(
    ["roles"],
    Result.flatMap(roles, (pair) =>
      pair[0] === pair[1] ? refuse(" must name two different roles") : Result.succeed(pair),
    ),
  );
}

const IAM_USER_MESSAGE = " must be an IAM user name";
const IAM_USER_FIELD = undefinedOr(
  IAM_USER_MESSAGE,
  stringLeaf(IAM_USER_MESSAGE, (raw) => IAM_USER.test(raw)),
);

function parseAwsRule(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
): Parsed<RotateRule> {
  return Result.gen(function* () {
    const accessKeyIdVariable = yield* field(
      value,
      "accessKeyIdVariable",
      envNameLeaf(" must name the variable holding the matching access key id"),
    );
    if (accessKeyIdVariable === name) {
      return yield* refuse(
        " must differ from the rule's own variable (the rule is keyed by the secret access key)",
        ["accessKeyIdVariable"],
      );
    }
    const user = yield* field(value, "user", IAM_USER_FIELD);
    const rule: RotateRule = {
      connector: "aws-iam-access-key",
      accessKeyIdVariable,
      user: user ?? null,
      inputs,
    };
    return rule;
  });
}

const CF_ACCOUNT_MESSAGE = " must be a Cloudflare account id (32 hex digits)";
const CF_ACCOUNT_FIELD = undefinedOr(
  CF_ACCOUNT_MESSAGE,
  stringLeaf(CF_ACCOUNT_MESSAGE, (raw) => CF_ACCOUNT.test(raw)),
);

function parseCloudflareRule(
  value: Record<string, unknown>,
  inputs: InputRefs,
): Parsed<RotateRule> {
  return Result.map(field(value, "accountId", CF_ACCOUNT_FIELD), (accountId): RotateRule => ({
    connector: "cloudflare-api-token",
    accountId: accountId ?? null,
    inputs,
  }));
}

const DB_HOST_MESSAGE = " must be the account's host part (default %)";
const DB_HOST = nullishOr(
  DB_HOST_MESSAGE,
  stringLeaf(DB_HOST_MESSAGE, (raw) => raw.length > 0 && raw.length <= 255 && !/['\\\s]/.test(raw)),
);

function parseDbRule(
  kind: "postgres" | "mysql",
  value: Record<string, unknown>,
  inputs: InputRefs,
): Parsed<RotateRule> {
  return Result.gen(function* () {
    const roles = yield* parseRoles(value);
    if (kind === "postgres") {
      const postgres: RotateRule = { connector: kind, roles, inputs };
      return postgres;
    }
    const host = yield* field(value, "host", DB_HOST);
    const mysql: RotateRule = { connector: kind, roles, host: host ?? "%", inputs };
    return mysql;
  });
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
const ARGV_MESSAGE =
  " must be the script's command: a non-empty list of strings whose first element is the executable (or that executable as one string)";
const ARGV = Schema.Union([
  Schema.String,
  Schema.Array(Schema.String.annotate({ message: ARGV_MESSAGE })),
])
  .annotate({ message: ARGV_MESSAGE })
  .check(
    Schema.makeFilter((argv) => {
      const executable = typeof argv === "string" ? argv : argv[0];
      return executable !== undefined && executable.trim().length > 0 ? undefined : ARGV_MESSAGE;
    }),
  );

function parseArgv(value: Record<string, unknown>, key: string): Parsed<readonly string[]> {
  return Result.map(field(value, key, ARGV), (argv) => (typeof argv === "string" ? [argv] : argv));
}

const CWD_MESSAGE =
  " must be a non-empty relative path (resolved from the rotation config's directory)";
const CWD = undefinedOr(
  CWD_MESSAGE,
  stringLeaf(CWD_MESSAGE, (raw) => raw.length > 0 && !isAbsolute(raw)),
);

/** The scripts' working directory: the config's directory, or a relative path joined onto it (an absolute path would not travel with the repository). */
function parseCwd(value: Record<string, unknown>, configDir: string): Parsed<string> {
  return Result.gen(function* () {
    const relativePath = yield* field(value, "cwd", CWD);
    if (relativePath === undefined) {
      return configDir;
    }
    const cwd = join(configDir, relativePath);
    // The scripts travel with the repository that holds the config; a cwd
    // that climbs out of its directory would run whatever lives there
    const inside = relative(configDir, cwd);
    if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) {
      return yield* refuse(
        ` must stay inside the rotation config's directory (${relativePath} climbs out of it)`,
        ["cwd"],
      );
    }
    return cwd;
  });
}

const COMPANIONS_MESSAGE =
  " must be an object (environment variable name → the maruhi variable it carries)";
const COMPANIONS = undefinedOr(COMPANIONS_MESSAGE, objectLeaf(COMPANIONS_MESSAGE));
const COMPANION_VARIABLE = envNameLeaf(
  " must name the maruhi variable it carries (letters, digits, _)",
);

function parseCompanions(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
): Parsed<Readonly<Record<string, string>>> {
  return Result.gen(function* () {
    const raw = (yield* field(value, "companions", COMPANIONS)) ?? {};
    const companions: Record<string, string> = {};
    for (const [envName, given] of Object.entries(raw)) {
      yield* refusal(
        companionNameRefusal(name, envName, Object.keys(inputs), Object.keys(companions)),
      );
      const variable = yield* at(["companions", envName], decode(COMPANION_VARIABLE, given));
      if (variable === name) {
        return yield* refuse(
          " must differ from the rule's own variable (the credential itself is injected under its name)",
          ["companions", envName],
        );
      }
      companions[envName] = variable;
    }
    return companions;
  });
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

const OUTPUT_MESSAGE =
  ' must be "value" (the script prints the new value) or "json" (an object with value, companions, facts)';
const OUTPUT = nullishOr(
  OUTPUT_MESSAGE,
  Schema.Literals(["value", "json"]).annotate({ message: OUTPUT_MESSAGE }),
);

/** The exec rule's answer shape: `output` and the companions it may carry. */
function parseExecAnswer(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
): Parsed<{
  readonly output: "value" | "json";
  readonly companions: Readonly<Record<string, string>>;
}> {
  return Result.gen(function* () {
    const output = (yield* field(value, "output", OUTPUT)) ?? "value";
    const companions = yield* parseCompanions(name, value, inputs);
    if (output === "value" && Object.keys(companions).length > 0) {
      return yield* refuse(' needs "output": "json" (only a JSON answer can carry companions)', [
        "companions",
      ]);
    }
    return { output, companions };
  });
}

function parseExecRule(
  name: string,
  value: Record<string, unknown>,
  inputs: InputRefs,
  configDir: string,
): Parsed<RotateRule> {
  return Result.gen(function* () {
    const rotate = yield* parseArgv(value, "rotate");
    const finalize =
      value["finalize"] === undefined || value["finalize"] === null
        ? null
        : yield* parseArgv(value, "finalize");
    const cwd = yield* parseCwd(value, configDir);
    yield* refusal(execNamesRefusal(name, inputs));
    const answer = yield* parseExecAnswer(name, value, inputs);
    const rule: RotateRule = { connector: "exec", rotate, finalize, cwd, ...answer, inputs };
    return rule;
  });
}

const CONNECTOR = Schema.Literals(ROTATE_CONNECTOR_KINDS).annotate({
  message: ` must be one of ${ROTATE_CONNECTOR_KINDS.join(", ")}`,
});

const RULE_RECORD = objectLeaf(" must be an object with a connector");

function parseRule(name: string, value: unknown, configDir: string): Parsed<RotateRule> {
  return Result.gen(function* () {
    const record = yield* decode(RULE_RECORD, value);
    // The rule's connector kind and the key check (the shape every rule shares)
    const kind = yield* field(record, "connector", CONNECTOR);
    yield* knownKeys(
      record,
      RULE_KEYS[kind],
      `a ${kind} rule accepts ${RULE_KEYS[kind].join(", ")}`,
    );
    const inputs = yield* parseInputs(name, kind, record);
    switch (kind) {
      case "aws-iam-access-key":
        return yield* parseAwsRule(name, record, inputs);
      case "cloudflare-api-token":
        return yield* parseCloudflareRule(record, inputs);
      case "postgres":
      case "mysql":
        return yield* parseDbRule(kind, record, inputs);
      case "exec":
        return yield* parseExecRule(name, record, inputs, configDir);
    }
  });
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

const VARIABLES_RECORD = objectLeaf(" must be an object (variable name → rule); it may be empty");

/** The `variables` object: every rule, then the companion-conflict check across them. */
function parseVariables(
  record: Record<string, unknown>,
  configDir: string,
): Parsed<ReadonlyMap<string, RotateRule>> {
  const variables = Result.gen(function* () {
    const raw = yield* decode(VARIABLES_RECORD, record["variables"]);
    const rules = new Map<string, RotateRule>();
    for (const [name, value] of Object.entries(raw)) {
      if (!SAFE_ENV_NAME.test(name)) {
        return yield* refuse(
          "variables keys must be variable names (letters, digits, _, starting with a letter or _)",
        );
      }
      rules.set(name, yield* at([name], parseRule(name, value, configDir)));
    }
    yield* refusal(companionConflict(rules));
    return rules;
  });
  return at(["variables"], variables);
}

/**
 * Parses the rotation config. `configDir` is the directory the config was
 * read from — the base of an `exec` rule's working directory (the scripts
 * travel with the repository, so they are named relative to the config).
 * The document is read in one pass: the header fields, then the rules —
 * the same order the reasons ran in before (the first one wins).
 */
export function parseRotateConfig(
  content: string,
  options: { readonly configDir?: string | undefined } = {},
): RotateConfig | Invalid {
  const configDir = options.configDir ?? ".";
  return parseConfigDocument(content, (record) =>
    Result.gen(function* () {
      const { projectId } = yield* configHeader(record, ROOT_KEYS);
      const variables = yield* parseVariables(record, configDir);
      const config: RotateConfig = { version: 1, projectId, variables };
      return config;
    }),
  );
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
export function configNamesProject(config: RotateConfig, projectId: ProjectId): boolean {
  return config.projectId === undefined || config.projectId === projectId;
}
