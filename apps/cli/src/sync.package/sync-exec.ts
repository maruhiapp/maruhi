// `maruhi sync`'s exec driver (integration-options.md §3
// supplement 10 / supplement 13 / supplement 14 / supplement 16).
//
// Launches an installed, signed-in vendor CLI (`wrangler` / `vercel`) as
// a child process and passes the value **on stdin alone**. argv carries
// only names and options: the argument template ({@link ArgTemplate})
// has no token for a value (prohibited by the type). A preset is
// declarative data (the command, the argument template, the stdin
// format, the per-process item count, telemetry-off environment
// variables, the value constraints, the options declaration), and
// adding one takes data + a fake-CLI check (`gh secret set NAME` came
// in via the declarations raw-value / one-at-a-time /
// `GH_TELEMETRY=false`).
//
// Measured behavior of the vendor CLIs (Vercel CLI confirmed at
// `readStandardInput` / `normalizeStdinEnvValue`, gh at
// `pkg/cmd/secret/set/set.go`):
//   - wrangler 4.128.0 `secret bulk`: stdin JSON `{"k":"v"}` in one
//     request, `null` = delete, 100 items per run, empty stdin exits 0
//     with "No content found" (→ never called with empty input),
//     `--name` / `--env`, `WRANGLER_SEND_METRICS=false` (strict
//     `true` / `false`)
//   - Vercel CLI 59.11.7 `env add NAME [env]`: reads only **the first
//     data chunk** of stdin after a 500 ms wait (→ write once and
//     close. Linux measured complete to 65,536 bytes; a macOS pipe has
//     an initial 16 KiB → cap is 16 KiB), strips exactly one trailing
//     newline only from a single-line value (→ a single-line value
//     ending in one newline cannot be represented, so refuse), empty
//     stdin = "no value" = interactive (→ refuse empty values),
//     `--force` = the API's upsert (no rm → add window), with
//     `--non-interactive` every prompt turns into a failure,
//     `VERCEL_TELEMETRY_DISABLED=1`
//   - gh 2.100.0 `secret set NAME`: with `--body` omitted and
//     non-interactive, reads **all** of stdin and
//     `bytes.TrimRight(body, "\r\n")` (→ strips every trailing CR / LF,
//     so a value ending in a newline — single-line or multi-line —
//     cannot be represented = refuse), an empty stdin is sealed and
//     sent as an empty body (the API's acceptance unconfirmed — the
//     refusal surfaces in gh's wording), sealing (a libsodium sealed
//     box) is client-side, overwrites, `gh secret delete NAME` (a
//     missing name is the API's 404 = nonzero), `-R OWNER/REPO` /
//     `--env <Environment>` / `--app
//     {actions|agents|codespaces|dependabot}` (Environment secrets are
//     actions-only), auth is `GH_TOKEN` (then `GITHUB_TOKEN`) or
//     `gh auth login`, signed-out is exit code 4, `GH_TELEMETRY=false` /
//     `DO_NOT_TRACK=1`. Names on the GitHub side must be alphanumerics
//     and `_`, cannot start with a digit or the `GITHUB_` prefix, and
//     are **stored in uppercase** (case-identical) — only uppercase
//     names are passed through so no two differently-cased names fold
//     into one secret (docs.github.com "Secrets reference")
//
// A vendor CLI's stdout / stderr is treated as able to contain a value:
// discarded on success, and on failure only the tail is shown with the
// values scrubbed ({@link scrubVendorOutput}).

import { Redacted } from "effect";

import { decodeValueText, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { ExecInput } from "./run.ts";
import type { OptionSpec, ResolvedOptions, ValueConstraints } from "./sync-types.ts";

/**
 * One argv token of a preset. A literal, the variable name, or a value taken
 * from the target's options. There is deliberately no token for the value.
 */
export type ArgTemplate =
  | string
  | { readonly kind: "name" }
  /** The required option's value verbatim (a positional argument). */
  | { readonly kind: "option"; readonly option: string }
  /** An optional option: the 2 tokens `flag value` when set. */
  | { readonly kind: "option"; readonly option: string; readonly flag: string }
  /** Adds `flag` as 1 token only when the boolean option equals `equals`. */
  | {
      readonly kind: "switch";
      readonly option: string;
      readonly equals: boolean;
      readonly flag: string;
    };

/** A declarative exec preset (data only — no code per vendor). */
export interface ExecPreset {
  /** The default executable (the installed CLI on PATH). */
  readonly command: string;
  /** The non-secret environment variables added to the child (telemetry off). */
  readonly env: Readonly<Record<string, string>>;
  /** The stdin format: one JSON object of name → value, or the value itself. */
  readonly transport: "json-object" | "raw-value";
  /** The maximum item count on one process (raw-value is always 1). */
  readonly batch: number;
  /** The write argv (without the command name). */
  readonly writeArgs: readonly ArgTemplate[];
  /** The delete: a JSON `null` (living inside the same write process) or another command's argv. */
  readonly delete: "json-null" | { readonly args: readonly ArgTemplate[] };
  readonly constraints: ValueConstraints;
  readonly options: Readonly<Record<string, OptionSpec>>;
  /**
   * The option names that build the destination's label (plan / apply's
   * header line — sync-plan.ts's describeDestination). Listed in
   * declaration order; only the set string values appear. Only
   * non-secret options are listed (token-like options do not exist to
   * begin with).
   */
  readonly describeOptions: readonly string[];
  /**
   * The options' mutual consistency (inexpressible in a single
   * `OptionSpec` — e.g. GitHub's Environment secrets exist for the
   * actions app only). Called at config time; on an inconsistency it
   * returns a string of the form `<option>: <reason>` (the same contract
   * as the http preset's `check`).
   */
  readonly check?: (options: ResolvedOptions) => string | null;
  /** The sign-in guidance `sync init` attaches (where the vendor CLI's credential lives and the minimum rights). */
  readonly signInHint?: string;
}

// A macOS pipe's initial capacity is 16 KiB (beyond it the writer blocks
// and Vercel CLI's "first chunk only" read truncates). Not Linux's
// measured 64 KiB ceiling — kept on the side that's safe across the
// environment difference
const VERCEL_MAX_VALUE_BYTES = 16 * 1024;

const VERCEL_ENVIRONMENTS = ["production", "preview", "development"] as const;

/**
 * Non-secret environment for every `gh` maruhi starts (`gh secret set` here, `gh
 * workflow run` in sync-push.ts): telemetry off, no update
 * check, and no interactive prompt (gh is already non-interactive when its stdio is
 * not a terminal; this cuts the prompt structurally).
 */
export const GH_ENV: Readonly<Record<string, string>> = {
  GH_TELEMETRY: "false",
  DO_NOT_TRACK: "1",
  GH_NO_UPDATE_NOTIFIER: "1",
  GH_PROMPT_DISABLED: "1",
};

// gh 2.100.0's `--app` closed set (shared.GetSecretApp). Omitted = actions
const GITHUB_SECRET_APPS = ["actions", "agents", "codespaces", "dependabot"] as const;

/**
 * GitHub secret names (docs.github.com "Secrets reference"): alphanumerics and `_`,
 * not starting with a digit, not starting with `GITHUB_`, stored in uppercase. Only
 * uppercase names are accepted so that no two maruhi names fold into one secret.
 */
const GITHUB_SECRET_NAME = /^(?!GITHUB_)[A-Z_][A-Z0-9_]*$/;

// gh's `-R [HOST/]OWNER/REPO`. Each segment's first character is
// alphanumeric (a leading `-` = the shape read as a flag is removed
// structurally: `-x/y` never passes)
const GITHUB_REPO = /^(?:[A-Za-z0-9][A-Za-z0-9.-]*\/)?[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]+$/;

// A GitHub Environment name (lands on gh's argv. Removes only a leading `-`, the shape read as a flag)
const GITHUB_ENVIRONMENT_NAME = /^[^-\s][^\n\r]*$/;

/**
 * Built-in exec presets (first-class targets — owner decision: Vercel /
 * Cloudflare Workers; GitHub Actions secrets through `gh`). Netlify has none:
 * `netlify env:set KEY value` takes the value as an argument, so the
 * only safe recipe is the http driver (sync-preset.ts declares why).
 */
export const EXEC_PRESETS = {
  "cloudflare-workers": {
    command: "wrangler",
    env: { WRANGLER_SEND_METRICS: "false", DO_NOT_TRACK: "1" },
    transport: "json-object",
    batch: 100,
    writeArgs: [
      "secret",
      "bulk",
      { kind: "option", option: "name", flag: "--name" },
      { kind: "option", option: "environment", flag: "--env" },
      { kind: "option", option: "config", flag: "--config" },
    ],
    delete: "json-null",
    constraints: { maxBytes: null, nonEmpty: false, trailingNewline: "kept", name: null },
    options: {
      name: { type: "string", required: false },
      environment: { type: "string", required: false },
      config: { type: "string", required: false },
    },
    // name unset = wrangler's config file holds it (visible on the cwd's output line)
    describeOptions: ["name", "environment"],
  },
  vercel: {
    command: "vercel",
    env: { VERCEL_TELEMETRY_DISABLED: "1" },
    transport: "raw-value",
    batch: 1,
    writeArgs: [
      "env",
      "add",
      { kind: "name" },
      { kind: "option", option: "environment" },
      { kind: "option", option: "gitBranch", flag: "--git-branch" },
      { kind: "option", option: "project", flag: "--project" },
      { kind: "option", option: "scope", flag: "--scope" },
      { kind: "switch", option: "sensitive", equals: false, flag: "--no-sensitive" },
      "--force",
      "--non-interactive",
    ],
    delete: {
      args: [
        "env",
        "rm",
        { kind: "name" },
        { kind: "option", option: "environment" },
        { kind: "option", option: "gitBranch", flag: "--git-branch" },
        { kind: "option", option: "project", flag: "--project" },
        { kind: "option", option: "scope", flag: "--scope" },
        "--yes",
        "--non-interactive",
      ],
    },
    constraints: {
      maxBytes: VERCEL_MAX_VALUE_BYTES,
      nonEmpty: true,
      trailingNewline: "strippedFromSingleLine",
      name: null,
    },
    options: {
      environment: { type: "string", required: true, values: VERCEL_ENVIRONMENTS },
      gitBranch: { type: "string", required: false },
      project: { type: "string", required: false },
      scope: { type: "string", required: false },
      sensitive: { type: "boolean", required: false },
    },
    // project unset = Vercel CLI's linked directory decides it (visible on the cwd's output line)
    describeOptions: ["project", "environment", "gitBranch"],
  },
  "github-actions": {
    command: "gh",
    env: GH_ENV,
    transport: "raw-value",
    batch: 1,
    writeArgs: [
      "secret",
      "set",
      { kind: "name" },
      { kind: "option", option: "repo", flag: "--repo" },
      { kind: "option", option: "environment", flag: "--env" },
      { kind: "option", option: "app", flag: "--app" },
    ],
    delete: {
      args: [
        "secret",
        "delete",
        { kind: "name" },
        { kind: "option", option: "repo", flag: "--repo" },
        { kind: "option", option: "environment", flag: "--env" },
        { kind: "option", option: "app", flag: "--app" },
      ],
    },
    constraints: {
      // GitHub's cap is 48 KB (docs) but the unit and the measurement are
      // unconfirmed, and gh reads all of stdin and hands it to the API
      // (no truncation path) = an overage surfaces as the API's refusal
      // in gh's wording. Don't depend on an unconfirmed number
      maxBytes: null,
      // gh seals an empty stdin as an empty body and sends it (never
      // read as no-value). A value of only newlines is refused earlier
      // by trailingNewline
      nonEmpty: false,
      trailingNewline: "stripped",
      name: {
        regex: GITHUB_SECRET_NAME,
        rule: "GitHub stores secret names in uppercase and accepts only uppercase letters, digits, and _, not starting with a digit or with GITHUB_",
      },
    },
    options: {
      repo: {
        type: "string",
        required: false,
        pattern: { regex: GITHUB_REPO, hint: "OWNER/REPO (or HOST/OWNER/REPO)" },
      },
      environment: {
        type: "string",
        required: false,
        pattern: {
          regex: GITHUB_ENVIRONMENT_NAME,
          hint: "a GitHub Environment name (not starting with -)",
        },
      },
      app: { type: "string", required: false, values: GITHUB_SECRET_APPS },
    },
    // repo unset = gh resolves it from cwd's git remote (visible on the cwd's output line)
    describeOptions: ["repo", "environment", "app"],
    // Environment secrets exist for the actions app only (gh's
    // shared.IsSupportedSecretEntity). gh refuses this **after** reading
    // the value from stdin, so it is stopped at config time
    check: (options) =>
      options["environment"] !== undefined &&
      options["app"] !== undefined &&
      options["app"] !== "actions"
        ? `app: environment secrets exist for GitHub Actions only, so app must be "actions" (or left out) when environment is set`
        : null,
    signInHint:
      "the github-actions preset runs the gh CLI, which must be installed and signed in (`gh auth login`, or GH_TOKEN in the environment) with write access to the repository's secrets: in a fine-grained token, Secrets for repository secrets, Environments for Environment secrets, Dependabot secrets for app dependabot (see the Deploy targets page in the docs)",
  },
} as const satisfies Readonly<Record<string, ExecPreset>>;

/** One variable to write at the target (the value stays wrapped until spawn). */
export interface SyncWrite {
  readonly name: string;
  readonly value: Redacted.Redacted<Uint8Array>;
}

/** One vendor-CLI process to run, with the names it carries (for reporting). */
export interface ExecInvocation extends ExecInput {
  readonly kind: "write" | "delete";
  readonly names: readonly string[];
}

/** One token's expansion (a value never lands — the template has no value token). */
function renderToken(
  template: ArgTemplate,
  options: Readonly<Record<string, string | boolean>>,
  name: string | null,
): readonly string[] {
  if (typeof template === "string") {
    return [template];
  }
  if (template.kind === "name") {
    // In a json-object write the name lives on stdin's JSON side and no
    // name token appears in the template (if one appears it's a
    // declaration mistake = internal error)
    if (name === null) {
      throw new Error("preset declares a name token for a batched command");
    }
    return [name];
  }
  if (template.kind === "switch") {
    return options[template.option] === template.equals ? [template.flag] : [];
  }
  const value = options[template.option];
  if (typeof value !== "string") {
    return [];
  }
  return "flag" in template ? [template.flag, value] : [value];
}

/** Expands the argument template into argv from the name and options. */
function renderArgs(
  templates: readonly ArgTemplate[],
  options: Readonly<Record<string, string | boolean>>,
  name: string | null,
): string[] {
  return templates.flatMap((template) => renderToken(template, options, name));
}

/** One value's constraint check (the wording carries only the variable name). */
export function checkValueConstraints(
  driver: { readonly constraints: ValueConstraints; readonly label: string },
  name: string,
  plaintext: Uint8Array,
): CliError | null {
  const shown = displayText(name);
  const { constraints, label } = driver;
  if (constraints.nonEmpty && plaintext.byteLength === 0) {
    return cliError(
      `Variable ${shown} is empty, and ${label} treats an empty value on stdin as no value. Set a non-empty value with \`maruhi push ${shown}\` or leave this variable out of the target`,
    );
  }
  if (constraints.maxBytes !== null && plaintext.byteLength > constraints.maxBytes) {
    return cliError(
      `Variable ${shown} is ${plaintext.byteLength} bytes, above the ${constraints.maxBytes}-byte limit maruhi applies for ${label} (it reads only the first chunk of stdin, so a larger value could be cut off silently). Leave this variable out of the target, or set it through the platform's dashboard`,
    );
  }
  if (
    constraints.trailingNewline === "strippedFromSingleLine" &&
    endsWithSingleLineNewline(plaintext)
  ) {
    return cliError(
      `Variable ${shown} is a single line ending with a newline, which ${label} strips from stdin. Push the value without the trailing newline (\`printf %s\` instead of \`echo\`), or leave this variable out of the target`,
    );
  }
  if (constraints.trailingNewline === "stripped" && endsWithNewline(plaintext)) {
    return cliError(
      `Variable ${shown} ends with a newline, which ${label} strips from stdin (every trailing CR or LF, from a single-line and a multi-line value alike). Push the value without the trailing newline (\`printf %s\` instead of \`echo\`), or leave this variable out of the target`,
    );
  }
  if (constraints.name !== null && !constraints.name.regex.test(name)) {
    return cliError(
      `Variable ${shown} has a name ${label} cannot store as is: ${constraints.name.rule}. Rename the variable in maruhi, or leave it out of the target`,
    );
  }
  return null;
}

/** Whether the tail is an LF or a CR (the shape where gh's `TrimRight("\r\n")` drops something). */
function endsWithNewline(bytes: Uint8Array): boolean {
  const last = bytes[bytes.length - 1];
  return last === 0x0a || last === 0x0d;
}

/** Whether "the tail is exactly one newline (LF / CRLF) and no other newline appears". */
function endsWithSingleLineNewline(bytes: Uint8Array): boolean {
  if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a) {
    return false;
  }
  const end =
    bytes.length > 1 && bytes[bytes.length - 2] === 0x0d ? bytes.length - 2 : bytes.length - 1;
  for (let index = 0; index < end; index += 1) {
    if (bytes[index] === 0x0a || bytes[index] === 0x0d) {
      return false;
    }
  }
  return true;
}

const encoder = new TextEncoder();

/**
 * Builds the processes to run for one target: writes (and deletes) in the
 * preset's transport, values only on stdin. Pure — nothing is spawned here.
 *
 * Assumes the caller (sync-plan.ts) has already done the UTF-8 check of
 * the value alongside `checkValueConstraints` (it must be text both as a
 * JSON string and as raw stdin). Here the Redacted is unwrapped and
 * **wrapped again** as the stdin byte string.
 */
export function buildInvocations(input: {
  readonly preset: ExecPreset;
  readonly command: string;
  readonly cwd: string;
  readonly options: Readonly<Record<string, string | boolean>>;
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
}): readonly ExecInvocation[] {
  const { preset } = input;
  const invocations: ExecInvocation[] = [];
  const base = (args: readonly string[]) => ({
    command: [input.command, ...args],
    cwd: input.cwd,
    extraEnv: preset.env,
  });
  if (preset.transport === "json-object") {
    // A JSON of name → value (a delete is null), `batch` items per process
    const entries: (readonly [string, string | null])[] = [
      ...input.writes.map((write) => {
        // Reason for unwrapping: assembling stdin's JSON body (the product is wrapped in Redacted again)
        const text = decodeValueText(Redacted.value(write.value));
        if (text === null) {
          // Assumes prepareWork (sync-plan.ts) filtered it before
          // sending. Reaching here = an implementation inconsistency, so
          // it drops rather than silently writing an empty string (the
          // worst shape). The wording carries neither the value nor the
          // variable name
          throw new Error("a value that is not valid UTF-8 reached buildInvocations");
        }
        return [write.name, text] as const;
      }),
      ...(preset.delete === "json-null" ? input.deletes.map((name) => [name, null] as const) : []),
    ];
    for (let start = 0; start < entries.length; start += preset.batch) {
      const chunk = entries.slice(start, start + preset.batch);
      invocations.push({
        ...base(renderArgs(preset.writeArgs, input.options, null)),
        kind: "write",
        names: chunk.map(([name]) => name),
        stdin: Redacted.make(encoder.encode(JSON.stringify(Object.fromEntries(chunk))), {
          label: "sync-stdin",
        }),
      });
    }
  } else {
    for (const write of input.writes) {
      invocations.push({
        ...base(renderArgs(preset.writeArgs, input.options, write.name)),
        kind: "write",
        names: [write.name],
        // The value as-is (no newline is appended — trailing newlines are checkValueConstraints' concern)
        stdin: write.value,
      });
    }
  }
  if (preset.delete !== "json-null") {
    for (const name of input.deletes) {
      invocations.push({
        ...base(renderArgs(preset.delete.args, input.options, name)),
        kind: "delete",
        names: [name],
        stdin: Redacted.make(new Uint8Array(0), { label: "sync-stdin" }),
      });
    }
  }
  return invocations;
}

/** The vendor output's line count shown on failure (the tail). */
const SHOWN_TAIL_LINES = 20;

/**
 * The character cap of the vendor output shown on failure (counted in
 * UTF-16 characters. A display cap, not a memory cap). Applied **after
 * scrubbing** — cutting before scrubbing would split a value at the
 * cut, leave its second half matching no fragment, and leak it.
 */
const SHOWN_TAIL_CHARS = 64 * 1024;

/** Keeps only the last `cap` characters (drops from the head). Used only on a scrubbed string. */
function keepTail(text: string, cap: number): string {
  return text.length <= cap ? text : text.slice(text.length - cap);
}

/**
 * Scrubs a vendor CLI's captured output for display: every synced value (and
 * every line of a multi-line one) is replaced over the whole output, control
 * characters are neutralized, and only then are the last lines kept. Best
 * effort — the output is shown only on failure, prefixed as filtered.
 */
export function scrubVendorOutput(
  output: string,
  values: readonly SyncWrite[],
  /** Secrets scrubbed besides the values (the http driver's integration token — could be echoed in a response). */
  tokens: readonly Redacted.Redacted<string>[] = [],
): string[] {
  let text = output;
  const fragments = new Set<string>();
  for (const token of tokens) {
    // Reason for unwrapping: scrubbing it out of the output (finds and replaces the token's fragments. It does not remain in the product)
    const secret = Redacted.value(token);
    if (secret.length > 0) {
      fragments.add(secret);
      fragments.add(JSON.stringify(secret).slice(1, -1));
    }
  }
  for (const write of values) {
    // Reason for unwrapping: scrubbing it out of the output (finds and replaces the value's fragments. It does not remain in the product)
    const plaintext = decodeValueText(Redacted.value(write.value));
    if (plaintext === null) {
      continue;
    }
    for (const fragment of [plaintext, ...plaintext.split(/\r?\n/)]) {
      if (fragment.length === 0) {
        continue;
      }
      fragments.add(fragment);
      // wrangler receives JSON, so if the body is echoed on failure the
      // value appears as a JSON string (escaped into `\"` / `\\` /
      // `\n`). The escaped form is also added to the fragments (if
      // identical to the raw form the set absorbs it)
      fragments.add(JSON.stringify(fragment).slice(1, -1));
    }
  }
  // Replaces from the longest fragment first (a short fragment must not crush part of a longer one and let it slip)
  for (const fragment of [...fragments].toSorted((a, b) => b.length - a.length)) {
    text = text.split(fragment).join("[redacted]");
  }
  const lines = keepTail(text, SHOWN_TAIL_CHARS)
    .split(/\r?\n/)
    .filter((line) => line.length > 0);
  return lines.slice(-SHOWN_TAIL_LINES).map((line) => displayText(line));
}
