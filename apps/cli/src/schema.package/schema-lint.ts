import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { countNoun, displayText, logWarnings } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import { pullVerifiedEnvironmentMetadata } from "../values.ts";

const NAME = "([A-Za-z_][A-Za-z0-9_]*)";

const REFERENCE_SOURCES: readonly string[] = [
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

const LEFT_BOUNDARY_SOURCE = String.raw`(?<![A-Za-z0-9_$.])`;

const REFERENCE_PATTERNS: readonly RegExp[] = REFERENCE_SOURCES.map(
  (source) => new RegExp(`${LEFT_BOUNDARY_SOURCE}${source}`, "g"),
);

const DESTRUCTURE_PATTERN = new RegExp(
  String.raw`\{([^{}]*)\}\s*=\s*${LEFT_BOUNDARY_SOURCE}(?:process\.env|import\.meta\.env|Bun\.env)(?![.\[?])`,
  "g",
);

function destructuredNames(inner: string): string[] {
  const names: string[] = [];
  const blanked = inner.replace(
    /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g,
    (m: string, offset: number, s: string) =>
      s[offset + m.length]?.trimStart().startsWith(":") ? m : '""',
  );
  for (const entry of blanked.split(",")) {
    const key = (entry.split("=")[0]?.split(":")[0] ?? "").trim().replace(/^["']|["']$/g, "");
    if (new RegExp(`^${NAME}$`).test(key)) {
      names.push(key);
    }
  }
  return names;
}

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

const MAX_FILE_BYTES = 1024 * 1024;

function extensionOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot < 0 ? "" : name.slice(dot);
}

async function collectSourceFiles(path: string, into: string[]): Promise<void> {
  const info = await stat(path);
  if (info.isFile()) {
    into.push(path);
    return;
  }
  if (!info.isDirectory()) {
    return;
  }
  const entries = await readdir(path, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
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

export interface LintScan {
  readonly scannedFiles: number;
  readonly references: ReadonlySet<string>;
}

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
    catch: () =>
      cliError("Could not scan the given paths (check that they exist and are readable)"),
  });
}

const BEST_EFFORT_NOTE =
  "this is a best-effort static scan of literal references — dynamic access " +
  "(e.g. process.env[name]), unsupported languages and generated code are not seen, " +
  "so an empty report is not a guarantee that code and schema agree. Variables " +
  "declared but not read here may be consumed dynamically or by another repository";

export const schemaLintOp = Effect.fn("schema-lint.schemaLintOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly scan: LintScan;
  readonly ignore: readonly string[];
}): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
  const scan = input.scan;
  const metadata = yield* pullVerifiedEnvironmentMetadata(input);
  yield* logWarnings(metadata.warnings);
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
  yield* logNote(BEST_EFFORT_NOTE);
  if (undeclared.length > 0) {
    return yield* Effect.fail(
      cliError(
        `The scanned code reads ${countNoun(undeclared.length, "environment variable")} not declared in environment ${environment} (listed on stdout). Declare them with \`maruhi schema set <NAME>\` (or \`maruhi schema import\`), or exclude non-maruhi runtime variables with --ignore <NAME>`,
      ),
    );
  }
});
