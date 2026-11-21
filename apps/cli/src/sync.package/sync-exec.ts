import { Redacted } from "effect";

import { decodeValueText, displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import type { ExecInput } from "../run.ts";
import type { OptionSpec, ResolvedOptions, ValueConstraints } from "./sync-types.ts";

export type ArgTemplate =
  | string
  | { readonly kind: "name" }
  | { readonly kind: "option"; readonly option: string }
  | { readonly kind: "option"; readonly option: string; readonly flag: string }
  | {
      readonly kind: "switch";
      readonly option: string;
      readonly equals: boolean;
      readonly flag: string;
    };

export interface ExecPreset {
  readonly command: string;
  readonly env: Readonly<Record<string, string>>;
  readonly transport: "json-object" | "raw-value";
  readonly batch: number;
  readonly writeArgs: readonly ArgTemplate[];
  readonly delete: "json-null" | { readonly args: readonly ArgTemplate[] };
  readonly constraints: ValueConstraints;
  readonly options: Readonly<Record<string, OptionSpec>>;
  readonly describeOptions: readonly string[];
  readonly check?: (options: ResolvedOptions) => string | null;
  readonly signInHint?: string;
}

const VERCEL_MAX_VALUE_BYTES = 16 * 1024;

const VERCEL_ENVIRONMENTS = ["production", "preview", "development"] as const;

export const GH_ENV: Readonly<Record<string, string>> = {
  GH_TELEMETRY: "false",
  DO_NOT_TRACK: "1",
  GH_NO_UPDATE_NOTIFIER: "1",
  GH_PROMPT_DISABLED: "1",
};

const GITHUB_SECRET_APPS = ["actions", "agents", "codespaces", "dependabot"] as const;

const GITHUB_SECRET_NAME = /^(?!GITHUB_)[A-Z_][A-Z0-9_]*$/;

const GITHUB_REPO = /^(?:[A-Za-z0-9][A-Za-z0-9.-]*\/)?[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]+$/;

const GITHUB_ENVIRONMENT_NAME = /^[^-\s][^\n\r]*$/;

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
      maxBytes: null,
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
    describeOptions: ["repo", "environment", "app"],
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

export interface SyncWrite {
  readonly name: string;
  readonly value: Redacted.Redacted<Uint8Array>;
}

export interface ExecInvocation extends ExecInput {
  readonly kind: "write" | "delete";
  readonly names: readonly string[];
}

function renderToken(
  template: ArgTemplate,
  options: Readonly<Record<string, string | boolean>>,
  name: string | null,
): readonly string[] {
  if (typeof template === "string") {
    return [template];
  }
  if (template.kind === "name") {
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

function renderArgs(
  templates: readonly ArgTemplate[],
  options: Readonly<Record<string, string | boolean>>,
  name: string | null,
): string[] {
  return templates.flatMap((template) => renderToken(template, options, name));
}

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

function endsWithNewline(bytes: Uint8Array): boolean {
  const last = bytes[bytes.length - 1];
  return last === 0x0a || last === 0x0d;
}

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
    const entries: (readonly [string, string | null])[] = [
      ...input.writes.map((write) => {
        const text = decodeValueText(Redacted.value(write.value));
        if (text === null) {
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

const SHOWN_TAIL_LINES = 20;

const SHOWN_TAIL_CHARS = 64 * 1024;

function keepTail(text: string, cap: number): string {
  return text.length <= cap ? text : text.slice(text.length - cap);
}

export function scrubVendorOutput(
  output: string,
  values: readonly SyncWrite[],
  tokens: readonly Redacted.Redacted<string>[] = [],
): string[] {
  let text = output;
  const fragments = new Set<string>();
  for (const token of tokens) {
    const secret = Redacted.value(token);
    if (secret.length > 0) {
      fragments.add(secret);
      fragments.add(JSON.stringify(secret).slice(1, -1));
    }
  }
  for (const write of values) {
    const plaintext = decodeValueText(Redacted.value(write.value));
    if (plaintext === null) {
      continue;
    }
    for (const fragment of [plaintext, ...plaintext.split(/\r?\n/)]) {
      if (fragment.length === 0) {
        continue;
      }
      fragments.add(fragment);
      fragments.add(JSON.stringify(fragment).slice(1, -1));
    }
  }
  for (const fragment of [...fragments].toSorted((a, b) => b.length - a.length)) {
    text = text.split(fragment).join("[redacted]");
  }
  const lines = keepTail(text, SHOWN_TAIL_CHARS)
    .split(/\r?\n/)
    .filter((line) => line.length > 0);
  return lines.slice(-SHOWN_TAIL_LINES).map((line) => displayText(line));
}
