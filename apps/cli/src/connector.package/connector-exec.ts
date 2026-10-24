// The `exec` connector (PF8 — the connector overview lives in
// connector.ts): a script of the repository creates the new credential.
// Its environment carries the current credential, its companions, the
// admin inputs and the control variables; its stdout is the new value, or
// a JSON answer with the companions and facts. Anything a script prints is
// scrubbed of every secret the run knows before it is shown. Finalize runs
// the rule's finalize script with the previous credential.

import { Effect, Redacted } from "effect";

import { countNoun, decodeValueText, displayText } from "../display.ts";
import {
  type CaptureOutcome,
  ProcessRunner,
  ScriptLeftoverError,
  ScriptStoppedError,
} from "../run.ts";
import { scrubVendorOutput, type SyncWrite } from "../sync.package/index.ts";
import {
  ConnectorError,
  type ConnectorOutcome,
  type CredentialValues,
  type FinalizeOutcome,
  reasonOf,
  type RotateInputs,
  type RotationSite,
} from "./connector-shared.ts";
import { EXEC_CONTROL_PREFIX, type RotateRule } from "./rotate-config.ts";

const decoder = new TextDecoder();
const encoder = new TextEncoder();

type ExecRule = Extract<RotateRule, { connector: "exec" }>;

/** The lines of a script's stderr shown on failure (the tail, scrubbed). */
const EXEC_SHOWN_LINES = 20;
/** The lines of a finalize script's stdout kept as facts. */
const EXEC_FACT_LINES = 10;

/** A secret the script could echo, in the shape the scrubber takes. */
function secretOf(name: string, bytes: Uint8Array): SyncWrite {
  return { name, value: Redacted.make(bytes, { label: "exec-secret" }) };
}

/** Scrubs script output of every secret it could carry and keeps the tail (the sync driver's discipline). */
function scrubbedLines(output: string, secrets: readonly SyncWrite[], lines: number): string[] {
  return scrubVendorOutput(output, secrets).slice(-lines);
}

/**
 * The environment of a script: the credential under the rule's variable
 * name and `MH_ROTATE_CURRENT`, its companions and the admin inputs under
 * their names (the `maruhi run` shape — every value is a UTF-8 text
 * without NUL, as an environment variable must be), and the control
 * variables. The previous credential (finalize) rides as
 * `MH_ROTATE_PREVIOUS`. Names were validated at config time; here only
 * the values can refuse, each naming the variable and never the value.
 */
const scriptEnvironment = Effect.fn("connector-exec.scriptEnvironment")(function* (input: {
  readonly rule: ExecRule;
  readonly site: RotationSite;
  readonly phase: "rotate" | "finalize";
  readonly current: CredentialValues;
  readonly previous: CredentialValues | null;
  readonly inputs: RotateInputs;
}): Effect.fn.Return<Readonly<Record<string, string>>, ConnectorError> {
  const env: Record<string, string> = {
    [`${EXEC_CONTROL_PREFIX}VARIABLE`]: input.site.variable,
    [`${EXEC_CONTROL_PREFIX}ENVIRONMENT`]: input.site.environmentId,
    [`${EXEC_CONTROL_PREFIX}PHASE`]: input.phase,
  };
  const set = (
    name: string,
    bytes: Uint8Array,
    what: string,
  ): Effect.Effect<void, ConnectorError> => {
    const text = decodeValueText(bytes);
    if (text === null || text.includes("\0")) {
      return new ConnectorError({
        message: `exec: ${what} is not a UTF-8 text without NUL, so it cannot be set in the script's environment`,
      });
    }
    return Effect.sync(() => {
      env[name] = text;
    });
  };
  yield* set(
    input.site.variable,
    input.current.primary,
    `the value of ${displayText(input.site.variable)}`,
  );
  yield* set(
    `${EXEC_CONTROL_PREFIX}CURRENT`,
    input.current.primary,
    `the value of ${displayText(input.site.variable)}`,
  );
  if (input.previous !== null) {
    yield* set(`${EXEC_CONTROL_PREFIX}PREVIOUS`, input.previous.primary, "the previous credential");
  }
  for (const [envName, variable] of Object.entries(input.rule.companions)) {
    const bytes = input.current.companions[envName];
    if (bytes !== undefined) {
      yield* set(envName, bytes, `the value of ${displayText(variable)}`);
    }
    // The companion the previous credential carried (the key id to
    // retire), when the finalize knows it (C-7)
    const previousBytes = input.previous?.companions[envName];
    if (previousBytes !== undefined) {
      yield* set(
        `${EXEC_CONTROL_PREFIX}PREVIOUS_${envName}`,
        previousBytes,
        `the previous value of ${displayText(variable)}`,
      );
    }
  }
  for (const [envName, bytes] of Object.entries(input.inputs)) {
    yield* set(envName, bytes, `the input ${displayText(envName)}`);
  }
  return env;
});

/** The secrets a script of this rotation could echo (scrubbed out of anything shown). */
function scriptSecrets(input: {
  readonly current: CredentialValues;
  readonly previous: CredentialValues | null;
  readonly inputs: RotateInputs;
  readonly produced?: CredentialValues | undefined;
}): SyncWrite[] {
  const secrets = [secretOf("current", input.current.primary)];
  for (const [name, bytes] of Object.entries(input.current.companions)) {
    secrets.push(secretOf(`current:${name}`, bytes));
  }
  if (input.previous !== null) {
    secrets.push(secretOf("previous", input.previous.primary));
    for (const [name, bytes] of Object.entries(input.previous.companions)) {
      secrets.push(secretOf(`previous:${name}`, bytes));
    }
  }
  for (const [name, bytes] of Object.entries(input.inputs)) {
    secrets.push(secretOf(`input:${name}`, bytes));
  }
  if (input.produced !== undefined) {
    secrets.push(secretOf("new", input.produced.primary));
    for (const [name, bytes] of Object.entries(input.produced.companions)) {
      secrets.push(secretOf(`new:${name}`, bytes));
    }
  }
  return secrets;
}

/** A capture that rejected, as the connector's error: stopped by maruhi (D-6), a leftover's output (D-14), or a launch failure. */
function captureFailure(
  error: unknown,
  phase: "rotate" | "finalize",
  script: string,
): ConnectorError {
  if (error instanceof ScriptStoppedError) {
    // Stopped by maruhi after it started (a flooded stdout) — not a
    // launch failure (ruling D revision, round 4); a rotate script had
    // started printing, so the credential may exist at the issuer (D-17)
    const created =
      phase === "rotate"
        ? ". The new credential may exist at the issuer: re-run the rotation once the script prints only the value (make it idempotent, or retire the unused credential at the issuer by hand)"
        : "";
    return new ConnectorError({
      message: `exec: the ${phase} script ${script} was stopped: ${error.message}${created}`,
    });
  }
  if (error instanceof ScriptLeftoverError) {
    // The script's own answer cannot be told from a leftover process's
    // output (D-14); a script that exited 0 may have created the
    // credential, so the recovery is named
    const created =
      error.exitCode === 0 && phase === "rotate"
        ? ". The script exited 0, so the new credential may exist at the issuer: re-run the rotation once the script redirects that output (make it idempotent, or retire the unused credential at the issuer by hand)"
        : "";
    return new ConnectorError({ message: `exec: ${error.message}${created}` });
  }
  const reason = reasonOf(error, "it could not be started");
  return new ConnectorError({
    message: `exec: the ${phase} script ${script} did not start: ${reason}`,
  });
}

/** Runs one script; a launch failure or a non-zero exit is a connector error naming the script and the scrubbed stderr tail. */
const runScript = Effect.fn("connector-exec.runScript")(function* (
  rule: ExecRule,
  argv: readonly string[],
  env: Readonly<Record<string, string>>,
  secrets: readonly SyncWrite[],
  phase: "rotate" | "finalize",
): Effect.fn.Return<CaptureOutcome, ConnectorError, ProcessRunner> {
  const runner = yield* ProcessRunner;
  const outcome = yield* Effect.tryPromise({
    try: () => runner.captureScript({ command: argv, cwd: rule.cwd, extraEnv: env }),
    catch: (error) => captureFailure(error, phase, argv[0] ?? ""),
  });
  if (outcome.exitCode !== 0) {
    const tail = scrubbedLines(outcome.stderr, secrets, EXEC_SHOWN_LINES);
    return yield* new ConnectorError({
      message: `exec: the ${phase} script ${argv[0] ?? ""} exited with code ${outcome.exitCode}${tail.length === 0 ? "" : ` (its stderr, filtered: ${tail.join(" | ")})`}`,
    });
  }
  return outcome;
});

/** The new value as the rotate script printed it: one trailing newline (LF or CRLF) is dropped, nothing else is touched. */
function valueFromStdout(stdout: Uint8Array): Effect.Effect<Uint8Array, ConnectorError> {
  let end = stdout.length;
  if (end > 0 && stdout[end - 1] === 0x0a) {
    end -= 1;
    if (end > 0 && stdout[end - 1] === 0x0d) {
      end -= 1;
    }
  }
  const value = stdout.subarray(0, end);
  if (value.length === 0) {
    return new ConnectorError({
      message:
        "exec: the rotate script printed no value on stdout (its stdout is the new credential; commentary belongs on stderr)",
    });
  }
  return producedText(value, "the value the rotate script printed on stdout");
}

interface ScriptAnswer {
  readonly values: CredentialValues;
  readonly facts: readonly string[];
}

/** The rotate script's stdout as a JSON object (anything else is refused with the contract spelled out). */
function jsonObjectFromStdout(
  stdout: Uint8Array,
): Effect.Effect<Record<string, unknown>, ConnectorError> {
  const text = decodeValueText(stdout);
  let parsed: unknown;
  try {
    parsed = text === null ? undefined : JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return new ConnectorError({
      message:
        'exec: the rotate script did not print a JSON object on stdout (the rule declares "output": "json": print {"value": "<new credential>", "companions": {…}, "facts": […]})',
    });
  }
  const record = parsed as Record<string, unknown>;
  const unknown = Object.keys(record).filter(
    (key) => !["value", "companions", "facts"].includes(key),
  );
  // The keys are the script's words: counted, never echoed
  if (unknown.length > 0) {
    return new ConnectorError({
      message: `exec: the rotate script's JSON answer has ${countNoun(unknown.length, "unknown key")}; it takes value, companions, facts`,
    });
  }
  return Effect.succeed(record);
}

/** One answered companion: declared by the rule and a non-empty string. */
function companionBytes(
  rule: ExecRule,
  name: string,
  value: unknown,
): Effect.Effect<Uint8Array, ConnectorError> {
  // The script's own words never reach an error message (a mistyped key
  // could be a credential): the message names what the rule declares
  if (!(name in rule.companions)) {
    return new ConnectorError({
      message: `exec: the rotate script answered a companion the rule does not declare (the rule declares ${declaredCompanions(rule)}); declare it under companions in the rotation config`,
    });
  }
  return producedBytes(value, `the companion ${displayText(name)} in the rotate script's answer`);
}

/** The declared companion names for a message ("STRIPE_KEY_ID", "none"). */
function declaredCompanions(rule: ExecRule): string {
  const names = Object.keys(rule.companions);
  return names.length === 0 ? "none" : names.map(displayText).join(", ");
}

/**
 * A produced value (the primary or a companion) as bytes: a non-empty
 * string of UTF-8 text without NUL — what a value must be to be injected
 * by `maruhi run` later. `what` names the value, never carries it.
 */
function producedBytes(value: unknown, what: string): Effect.Effect<Uint8Array, ConnectorError> {
  if (typeof value !== "string" || value.length === 0) {
    return new ConnectorError({ message: `exec: ${what} is not a non-empty string` });
  }
  return producedText(encoder.encode(value), what);
}

/** The produced bytes checked as UTF-8 text without NUL (a value that could not be injected is refused before it is stored). */
function producedText(bytes: Uint8Array, what: string): Effect.Effect<Uint8Array, ConnectorError> {
  const text = decodeValueText(bytes);
  if (text === null || text.includes("\0")) {
    return new ConnectorError({
      message: `exec: ${what} is not UTF-8 text without NUL, so it could never be injected into a process environment; it is refused before anything is stored`,
    });
  }
  return Effect.succeed(bytes);
}

/** The answer's companions: every one the rule declares, nothing it does not, each a non-empty string. */
const companionsFromAnswer = Effect.fn("connector-exec.companionsFromAnswer")(function* (
  rule: ExecRule,
  raw: unknown,
): Effect.fn.Return<Record<string, Uint8Array>, ConnectorError> {
  const companionsRaw = raw ?? {};
  if (typeof companionsRaw !== "object" || companionsRaw === null || Array.isArray(companionsRaw)) {
    return yield* new ConnectorError({
      message: "exec: the rotate script's JSON answer has a companions field that is not an object",
    });
  }
  const companions: Record<string, Uint8Array> = {};
  for (const [name, value] of Object.entries(companionsRaw as Record<string, unknown>)) {
    companions[name] = yield* companionBytes(rule, name, value);
  }
  const missing = Object.keys(rule.companions).find((name) => !(name in companions));
  if (missing !== undefined) {
    return yield* new ConnectorError({
      message: `exec: the rotate script's answer lacks the companion ${displayText(missing)} the rule declares (every declared companion is pushed with the new value, so all of them must be answered)`,
    });
  }
  return companions;
});

/** The rotate script's JSON answer: `{ value, companions?, facts? }`. */
const answerFromJson = Effect.fn("connector-exec.answerFromJson")(function* (
  rule: ExecRule,
  stdout: Uint8Array,
): Effect.fn.Return<ScriptAnswer, ConnectorError> {
  const record = yield* jsonObjectFromStdout(stdout);
  const primary = yield* producedBytes(
    record["value"],
    "the value in the rotate script's JSON answer",
  );
  const companions = yield* companionsFromAnswer(rule, record["companions"]);
  const factsRaw = record["facts"] ?? [];
  if (!Array.isArray(factsRaw) || !factsRaw.every((fact) => typeof fact === "string")) {
    return yield* new ConnectorError({
      message:
        "exec: the rotate script's JSON answer has a facts field that is not a list of strings",
    });
  }
  return { values: { primary, companions }, facts: factsRaw as string[] };
});

export const rotateExec = Effect.fn("connector-exec.rotateExec")(function* (
  rule: ExecRule,
  site: RotationSite,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<ConnectorOutcome, ConnectorError, ProcessRunner> {
  const env = yield* scriptEnvironment({
    rule,
    site,
    phase: "rotate",
    current,
    previous: null,
    inputs,
  });
  const secrets = scriptSecrets({ current, previous: null, inputs });
  const outcome = yield* runScript(rule, rule.rotate, env, secrets, "rotate");
  const answer: ScriptAnswer =
    rule.output === "json"
      ? yield* answerFromJson(rule, outcome.stdout)
      : {
          values: { primary: yield* valueFromStdout(outcome.stdout), companions: {} },
          facts: [],
        };
  // The script's own words may carry a credential by mistake: scrub them
  // of everything this run knows before they reach the report
  const all = scriptSecrets({ current, previous: null, inputs, produced: answer.values });
  const facts = answer.facts.flatMap((fact) => scrubbedLines(fact, all, 1));
  const script = rule.rotate[0] ?? "";
  return {
    values: answer.values,
    facts: [
      `${script}: new credential produced${facts.length === 0 ? "" : ` (${facts.join("; ")})`}`,
    ],
    previous:
      rule.finalize === null
        ? "the rotate script was expected to retire the previous credential itself (nothing to finalize)"
        : `the previous credential stays valid until you finalize (${rule.finalize[0] ?? ""} runs with it)`,
    recovery: `the new credential is held only by this process (it is not shown) — re-run the rotation (${script} runs again; make it idempotent, or retire the unused credential at the issuer by hand)`,
    warnings: [],
  };
});

export const finalizeExec = Effect.fn("connector-exec.finalizeExec")(function* (
  rule: ExecRule,
  site: RotationSite,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<FinalizeOutcome, ConnectorError, ProcessRunner> {
  if (rule.finalize === null) {
    return {
      kind: "nothing" as const,
      facts: [
        "the rule has no finalize script (its rotate script retires the previous credential itself)",
      ],
    };
  }
  const env = yield* scriptEnvironment({
    rule,
    site,
    phase: "finalize",
    current,
    previous,
    inputs,
  });
  const secrets = scriptSecrets({ current, previous, inputs });
  const outcome = yield* runScript(rule, rule.finalize, env, secrets, "finalize");
  const said = scrubbedLines(decoder.decode(outcome.stdout), secrets, EXEC_FACT_LINES);
  return {
    kind: "finalized" as const,
    facts: [
      `${rule.finalize[0] ?? ""}: previous credential retired${said.length === 0 ? "" : ` (${said.join("; ")})`}`,
    ],
  };
});
