// `maruhi schema lint` (finding G — design doc §1-7).
//
// Statically scans the sources' env references (`process.env.X` etc.)
// and cross-checks them against the verified store-side schema (the set
// of live variable names — active + declared): "the code reads FOO but
// the schema has no declaration / the reverse".
//
// **Best-effort, good-faith drift detection** (the same positioning as
// the BG tripwire): dynamic access (`process.env[name]`), unsupported
// languages, and string-assembled names cannot be caught. Always include
// the caveat that keeps a gap in checking from being conflated with a
// gap in the guarantee (§1-7).
//
// The scanner is **self-built and regex-based** (the spec fixes only the
// positioning — no new code-parser dependency is added). The supported
// read forms (implementation ruling — only the static literal forms of
// the major runtimes):
//   JS/TS: process.env.X / process.env["X"] / import.meta.env.X / Bun.env.X /
//          Deno.env.get("X") (member references may use optional
//          chaining `?.`), plus destructuring of an env object
//          `const { X, Y: alias, Z = "default" } = process.env`
//          (the most frequent idiom — missing it would make the
//          undeclared-side tripwire swing at typical JS code)
//   Python: os.environ["X"] / os.environ.get("X") / os.getenv("X")
//   Go:     os.Getenv("X") / os.LookupEnv("X")
//   Ruby:   ENV["X"] / ENV.fetch("X")
//   Rust:   env::var("X") / env::var_os("X") (with or without the std::
//           prefix)
// A shell's `$X` is not supported (a shell variable and an env reference
// cannot be told apart statically — false positives would dominate. The
// best-effort line).
//
// **The report carries only variable names** (no descriptions — §1-7 /
// §2's consumption-point discipline. Reports flow into logs and CI).
// Names are neutralized via displayText (whether code-sourced or
// store-sourced, neutralizing terminal injection is the display side's
// independent duty — ruling CW).
//
// **The exit-code ruling (an implementation ruling — recorded in the PR
// body)**: "read by the code but undeclared" is exit 1 (fail-loud —
// evidence the scan **found**, the precursor of run's presence
// fail-fast). "Declared but not read by the code" is report-only
// (exit 0) — it legitimately arises from dynamic access, consumption by
// another repository, or a child process's reads via run, and wiring a
// best-effort scan's gap straight to a CI failure goes the direction of
// conflating "a gap in checking" with "a gap in the guarantee". The
// line against env diff's "nonzero diff, still 0": diff is a **report**
// between environments (a machine cannot decide which is right), lint
// is a **check** of a code contract (the code is the authority —
// finding G).

import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { countNoun, displayText, logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironmentMetadata } from "./values.ts";

/** The identifier shape caught as an environment variable name (the customary POSIX env-var name). */
const NAME = "([A-Za-z_][A-Za-z0-9_]*)";

/** The patterns of static literal env references (the `${NAME}` position = the variable-name capture). */
const REFERENCE_SOURCES: readonly string[] = [
  // A JS member reference with optional chaining (`process.env?.X`) is the same shape of literal reference
  String.raw`process\.env\??\.${NAME}`,
  String.raw`process\.env\[["']${NAME}["']\]`,
  String.raw`import\.meta\.env\??\.${NAME}`,
  String.raw`Bun\.env\??\.${NAME}`,
  String.raw`Bun\.env\[["']${NAME}["']\]`,
  String.raw`Deno\.env\.get\(\s*["']${NAME}["']\s*\)`,
  String.raw`os\.environ\[["']${NAME}["']\]`,
  String.raw`os\.environ\.get\(\s*["']${NAME}["']`,
  String.raw`os\.getenv\(\s*["']${NAME}["']`,
  String.raw`os\.(?:Getenv|LookupEnv)\(\s*"${NAME}"\s*\)`,
  String.raw`ENV(?:\.fetch\(\s*|\[)["']${NAME}["']`,
  String.raw`(?:std::)?env::var(?:_os)?\(\s*"${NAME}"\s*\)`,
];

/**
 * The shared left boundary of every pattern: no match when the character
 * just before continues an identifier (alphanumeric / `_` / `$`) or is a
 * member-access `.`. Blocks mistaking an "identifier that happens to end
 * in ENV" — `MY_ENV["FOO"]` / `TEST_ENV.fetch("BAR")` — for an env
 * reference and taking CI to exit 1. `\b` is not enough (`_` is a word
 * character).
 */
const LEFT_BOUNDARY_SOURCE = String.raw`(?<![A-Za-z0-9_$.])`;

const REFERENCE_PATTERNS: readonly RegExp[] = REFERENCE_SOURCES.map(
  (source) => new RegExp(`${LEFT_BOUNDARY_SOURCE}${source}`, "g"),
);

/**
 * Destructuring an env object (`const { X, Y: alias, Z = "d" } =
 * process.env`). Capture 1 = everything inside the braces (name
 * extraction is destructuredNames). `[^{}]*` spans newlines
 * (multi-line destructuring). Nested destructures are out of scope.
 */
const DESTRUCTURE_PATTERN = new RegExp(
  String.raw`\{([^{}]*)\}\s*=\s*${LEFT_BOUNDARY_SOURCE}(?:process\.env|import\.meta\.env|Bun\.env)(?![.\[?])`,
  "g",
);

/** Extract env names from inside a destructure's braces (the left side of a rename / of a default). */
function destructuredNames(inner: string): string[] {
  const names: string[] = [];
  // A value-side string literal is crushed to `""` — even when a default
  // value contains a comma (`{ LIST = "a,b" }`) it is not treated as a
  // split point (prevents a phantom identifier from mixing into
  // undeclared and false-failing the lint). A quote immediately followed
  // by `:` is a key (`"QUOTED_VAR": q`), so it is kept
  const blanked = inner.replace(
    /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g,
    (m: string, offset: number, s: string) =>
      s[offset + m.length]?.trimStart().startsWith(":") ? m : '""',
  );
  for (const entry of blanked.split(",")) {
    // `Y: alias` takes the left side (the property name = the env name);
    // `Z = "d"` also takes the left side. A quoted key (`"X": v`) is
    // unquoted and accepted only if identifier-shaped (`...rest` or a
    // computed property does not match and drops naturally)
    const key = (entry.split("=")[0]?.split(":")[0] ?? "").trim().replace(/^["']|["']$/g, "");
    if (new RegExp(`^${NAME}$`).test(key)) {
      names.push(key);
    }
  }
  return names;
}

/** Scans one file's text for literal environment-variable references. */
export function scanEnvReferences(content: string): ReadonlySet<string> {
  const names = new Set<string>();
  for (const pattern of REFERENCE_PATTERNS) {
    for (const match of content.matchAll(pattern)) {
      const name = match[1];
      if (name !== undefined) {
        names.add(name);
      }
    }
  }
  for (const match of content.matchAll(DESTRUCTURE_PATTERN)) {
    for (const name of destructuredNames(match[1] ?? "")) {
      names.add(name);
    }
  }
  return names;
}

/** The extensions scanned (only sources of languages with a supported pattern — keeps false positives down). */
const SOURCE_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".mts",
  ".cts",
  ".py",
  ".rb",
  ".go",
  ".rs",
]);

/** Generated-artifact / dependency directories are not scanned (only the source contract is read). */
const SKIPPED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  "target",
  "vendor",
  "coverage",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
]);

/** The per-file scan cap (keeps generated artifacts / data files from being swept in). */
const MAX_FILE_BYTES = 1024 * 1024;

function extensionOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot < 0 ? "" : name.slice(dot);
}

/** Recursively collects scannable source files under one path (best effort). */
async function collectSourceFiles(path: string, into: string[]): Promise<void> {
  const info = await stat(path);
  if (info.isFile()) {
    // An explicitly specified file is not filtered by extension (never silently ignore the user's designation)
    into.push(path);
    return;
  }
  if (!info.isDirectory()) {
    return;
  }
  const entries = await readdir(path, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      // Symlinks are never followed (never build a cycle or an escape outside the repository)
      continue;
    }
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRECTORIES.has(entry.name)) {
        await collectSourceFiles(join(path, entry.name), into);
      }
      continue;
    }
    if (entry.isFile() && SOURCE_EXTENSIONS.has(extensionOf(entry.name))) {
      into.push(join(path, entry.name));
    }
  }
}

/** The scan's result (raw data before cross-checking). */
export interface LintScan {
  readonly scannedFiles: number;
  readonly references: ReadonlySet<string>;
}

/** Walks the given paths and scans every supported source file. */
export function scanPaths(paths: readonly string[]): Effect.Effect<LintScan, CliError> {
  return Effect.tryPromise({
    try: async () => {
      const files: string[] = [];
      for (const path of paths) {
        await collectSourceFiles(path, files);
      }
      const references = new Set<string>();
      let scannedFiles = 0;
      for (const file of files) {
        const info = await stat(file);
        if (info.size > MAX_FILE_BYTES) {
          continue;
        }
        const content = await readFile(file, "utf8");
        // A swept-in binary is detected by a NUL and skipped (extensions can be faked)
        if (content.includes("\u0000")) {
          continue;
        }
        scannedFiles += 1;
        for (const name of scanEnvReferences(content)) {
          references.add(name);
        }
      }
      return { scannedFiles, references };
    },
    // The paths are the user's input so they may go in the error (they
    // are not values), but the OS error's detail is not carried (the same
    // discipline as schema import's file reading)
    catch: () =>
      cliError("Could not scan the given paths (check that they exist and are readable)"),
  });
}

const BEST_EFFORT_NOTE =
  "this is a best-effort static scan of literal references — dynamic access " +
  "(e.g. process.env[name]), unsupported languages and generated code are not seen, " +
  "so an empty report is not a guarantee that code and schema agree. Variables " +
  "declared but not read here may be consumed dynamically or by another repository";

/**
 * Cross-checks scanned environment-variable references against the
 * environment's verified live variable names (finding G — §1-7). The scan is
 * the caller's input (`scanPaths` — run before any network access so a bad
 * path fails without a round trip). Reports carry variable names only. Exit
 * is non-zero only for the hard direction (code reads a name the store does
 * not declare).
 */
export function schemaLintOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly scan: LintScan;
  /** Names excluded from the undeclared side (non-maruhi-managed like NODE_ENV — explicitly specified). */
  readonly ignore: readonly string[];
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const scan = input.scan;
    const metadata = yield* pullVerifiedEnvironmentMetadata(input);
    yield* logWarnings(metadata.warnings);
    // The cross-check's target is the names of the verified live set (a
    // v1 variable's name is also first-class — counted as "a variable the
    // store holds" regardless of the schema column. What is being
    // fabricated is not a name)
    const declaredNames = new Set(metadata.variables.map((statement) => statement.name));
    const ignored = new Set(input.ignore);
    const undeclared = [...scan.references]
      .filter((name) => !declaredNames.has(name) && !ignored.has(name))
      .toSorted();
    const unread = [...declaredNames].filter((name) => !scan.references.has(name)).toSorted();
    const environment = displayText(input.environmentId);
    yield* io.log(
      `Scanned ${countNoun(scan.scannedFiles, "source file")} (${countNoun(scan.references.size, "distinct environment-variable reference")})`,
    );
    // The count lines are emitted even at 0 (the output's shape does not vary by run — env diff's discipline)
    yield* io.log(
      `Read by the scanned code but not declared in environment ${environment}: ${undeclared.length}`,
    );
    for (const name of undeclared) {
      yield* io.log(`  ${displayText(name)}`);
    }
    yield* io.log(
      `Declared in environment ${environment} but not read by the scanned code: ${unread.length}`,
    );
    for (const name of unread) {
      yield* io.log(`  ${displayText(name)}`);
    }
    // The best-effort caveat is always emitted regardless of the
    // conclusion (a gap in checking is not a gap in the guarantee —
    // stderr: it is advice, not the command's output)
    yield* logNote(BEST_EFFORT_NOTE);
    if (undeclared.length > 0) {
      return yield* Effect.fail(
        cliError(
          `The scanned code reads ${countNoun(undeclared.length, "environment variable")} not declared in environment ${environment} (listed on stdout). Declare them with \`maruhi schema set <NAME>\` (or \`maruhi schema import\`), or exclude non-maruhi runtime variables with --ignore <NAME>`,
        ),
      );
    }
  });
}
