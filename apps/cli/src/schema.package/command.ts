// `maruhi schema` (discipline: see commands/index.ts).

import { readFile } from "node:fs/promises";

import { MAX_META_MAX_AGE_DAYS, type MetaVarType } from "@maruhi/crypto";
import { Effect } from "effect";
import { Argument, Command, Flag } from "effect/cli";

import { NonBlank, commonFlags, singleFlag, singleValued } from "../commands/flags.ts";
import { type CliServices, openEnvironment, openMetadataEnvironment } from "../context.ts";
import { displayText, logWarnings } from "../display.ts";
import { CliError, cliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import { ensureImportCeremonyAllowed, schemaImportOp } from "./schema-import.ts";
import { scanPaths, schemaLintOp } from "./schema-lint.ts";
import { schemaExportOp, schemaVerifySnapshotOp } from "./schema-snapshot.ts";
import {
  type FieldUpdate,
  type SchemaFieldUpdates,
  type SchemaSetSummary,
  ensureEntropyAcknowledged,
  schemaSetOp,
  schemaShowOp,
} from "./schema.ts";

/** `maruhi schema` (display — the bare parent doubles as show. Same shape as audit).
 * @public
 */
export const schemaShowConfig = { ...commonFlags() };

/** The `--type` closed set (CRYPTO_SPEC §4.2 — ruling CT) + `none` for an explicit clear. */
const SCHEMA_TYPES = ["string", "number", "boolean", "url"] as const;
/** @public */
export const schemaSetConfig = {
  ...commonFlags(),
  type: singleValued(
    "type",
    `Declared value type (${SCHEMA_TYPES.join(" | ")}; \`none\` clears it back to unspecified)`,
  ),
  required: singleFlag(
    "required",
    "Declare the variable as required (`maruhi run` fails fast while it has no value)",
  ),
  optional: singleFlag("optional", "Declare the variable as not required"),
  description: singleValued(
    "description",
    "Human-readable description (plaintext metadata visible to the server — never put secret values here)",
  ),
  "clear-description": singleFlag(
    "clear-description",
    "Clear the description (explicit — an empty --description value is rejected as a likely unset shell variable)",
  ),
  "max-age": singleValued(
    "max-age",
    "Days within which a value should be replaced after its push (1 to 3650), or `none` to clear it; `maruhi rotation list` shows values past their max age",
  ),
  "allow-high-entropy": singleFlag(
    "allow-high-entropy",
    "Proceed without confirmation when the name or description contains a secret-like high-entropy string (fail-closed otherwise)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription(
      "Variable name (created as a declared variable when it does not exist)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi schema import <file>` (bootstrap — design doc §1-3).
 * @public
 */
export const schemaImportConfig = {
  ...commonFlags(),
  file: Argument.String("file").pipe(
    Argument.withDescription(
      "Path to a .env or .env.example file to read locally (values are observed for type inference only; never sent unless you explicitly choose to push one)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi schema export` (producing the derived snapshot — design doc §1-6).
 * @public
 */
export const schemaExportConfig = { ...commonFlags() };

/** `maruhi schema verify-snapshot <file>` (the CI divergence check — design doc §1-6).
 * @public
 */
export const schemaVerifySnapshotConfig = {
  ...commonFlags(),
  file: Argument.String("file").pipe(
    Argument.withDescription(
      "Path to the committed snapshot file (generate with `maruhi schema export`)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi schema lint [paths...]` (matching against the code contract — design doc §1-7).
 * @public
 */
export const schemaLintConfig = {
  ...commonFlags(),
  ignore: Flag.String("ignore").pipe(
    Flag.withDescription(
      "Environment-variable name to exclude from the undeclared check (repeatable; for runtime variables not managed by maruhi, e.g. NODE_ENV)",
    ),
    Flag.withSchema(NonBlank),
    // Express repetition in the declaration (0 or more — atLeast(0) gives readonly string[])
    Flag.atLeast(0),
  ),
  paths: Argument.String("path").pipe(
    Argument.withDescription("File or directory to scan for environment-variable references"),
    Argument.atLeast(1),
  ),
};

/**
 * `maruhi schema` (display)'s body (shared between bare `maruhi schema`
 * and the parent handler — same shape as audit). **The keyless class**
 * (openMetadataEnvironment — a metadata-only pull) and **agent-gate does
 * not apply (the permissive side — design doc §1-1)**: the output carries
 * zero values (names, types, descriptions, required, status only), and
 * ADR-0016 decision 7's two-layer gate applies only to "value-displaying"
 * commands. Running as-is in an agent environment is this feature's main
 * use (not being on the deny-list is pinned by a test).
 */
function runSchemaShow(values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const context = yield* openMetadataEnvironment(values);
    yield* schemaShowOp({
      client: context.client,
      verified: context.verified,
      environmentId: context.environmentId,
      resync: context.resync,
      floor: context.floorHandle,
    });
  });
}

/** Interpreting `--type` (unspecified = keep, `none` = an explicit clear. **The given value itself never appears in the error**). */
function parseSchemaTypeFlag(
  value: string | undefined,
): Effect.Effect<FieldUpdate<MetaVarType>, CliError> {
  if (value === undefined) {
    return Effect.succeed({ kind: "keep" });
  }
  if (value === "none") {
    return Effect.succeed({ kind: "set", value: "" });
  }
  if ((SCHEMA_TYPES as readonly string[]).includes(value)) {
    return Effect.succeed({ kind: "set", value: value as MetaVarType });
  }
  return Effect.fail(
    usageError(`--type must be one of ${SCHEMA_TYPES.join(" | ")} (or \`none\` to clear it)`),
  );
}

/** Interpreting `--max-age` (unspecified = keep, `none` = clear, else a day count 1..3650). The given text never appears in the error. */
function parseMaxAgeFlag(
  value: string | undefined,
): Effect.Effect<FieldUpdate<number | null>, CliError> {
  if (value === undefined) {
    return Effect.succeed({ kind: "keep" });
  }
  if (value === "none") {
    return Effect.succeed({ kind: "set", value: null });
  }
  const days = /^[1-9][0-9]{0,3}$/.test(value) ? Number(value) : Number.NaN;
  return Number.isInteger(days) && days >= 1 && days <= MAX_META_MAX_AGE_DAYS
    ? Effect.succeed({ kind: "set", value: days })
    : Effect.fail(
        usageError(
          `--max-age must be a number of days from 1 to ${MAX_META_MAX_AGE_DAYS} (or \`none\` to clear it)`,
        ),
      );
}

/**
 * Interpreting `schema set`'s column specifications (partial update §1-2
 * — unspecified = keep, only an explicit flag returns to empty). A
 * contradictory specification (--required and --optional etc.) is a usage
 * error.
 */
function parseSchemaFieldUpdates(values: {
  readonly type?: string | undefined;
  readonly required: boolean;
  readonly optional: boolean;
  readonly description?: string | undefined;
  readonly "clear-description": boolean;
  readonly "max-age"?: string | undefined;
}): Effect.Effect<SchemaFieldUpdates, CliError> {
  return Effect.gen(function* () {
    const varType = yield* parseSchemaTypeFlag(values.type);
    const maxAgeDays = yield* parseMaxAgeFlag(values["max-age"]);
    if (values.required && values.optional) {
      return yield* Effect.fail(
        usageError("--required and --optional are mutually exclusive (specify at most one)"),
      );
    }
    const required: FieldUpdate<boolean> = values.required
      ? { kind: "set", value: true }
      : values.optional
        ? { kind: "set", value: false }
        : { kind: "keep" };
    if (values.description !== undefined && values["clear-description"]) {
      return yield* Effect.fail(
        usageError("--description and --clear-description are mutually exclusive"),
      );
    }
    const description: FieldUpdate<string> = values["clear-description"]
      ? { kind: "set", value: "" }
      : values.description !== undefined
        ? { kind: "set", value: values.description }
        : { kind: "keep" };
    return { varType, required, description, maxAgeDays };
  });
}

/** `schema set`'s success report (the type is displayed as a declaration — the word "verified" is never used, §14.3). */
function schemaSetReport(name: string, summary: SchemaSetSummary): string {
  const typeShown = summary.schema.varType === "" ? "-" : summary.schema.varType;
  const maxAge =
    summary.schema.maxAgeDays === null ? "" : `, max-age=${summary.schema.maxAgeDays}d`;
  if (summary.created) {
    return `Declared ${displayText(name)} (type=${typeShown}, required=${summary.schema.required}${maxAge}) — no value yet. Set the first value with: \`printf %s "$VALUE" | maruhi push ${displayText(name)}\``;
  }
  return `Updated the schema of ${displayText(name)} (type=${typeShown}, required=${summary.schema.required}${maxAge}, metaVersion=${summary.metaVersion})`;
}
/** @public */
export function makeSchemaCommands() {
  const schemaSet = Command.make("set", schemaSetConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // Interpreting the column specifications precedes the network
      // (partial update §1-2 — unspecified = keep, only an explicit flag
      // returns to empty)
      const updates = yield* parseSchemaFieldUpdates(values);
      // The entropy warning (ruling CW — fail-closed) is judged before communication / signing
      yield* ensureEntropyAcknowledged({
        fields: [
          { field: "name", text: values.name },
          ...(updates.description.kind === "set"
            ? [{ field: "description" as const, text: updates.description.value }]
            : []),
        ],
        allowHighEntropy: values["allow-high-entropy"],
      });
      const context = yield* openEnvironment(values);
      const summary = yield* schemaSetOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        name: values.name,
        updates,
        resync: context.resync,
        floor: context.floorHandle,
        authorUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
      });
      yield* logWarnings(summary.warnings);
      yield* io.log(schemaSetReport(values.name, summary));
    }),
  ).pipe(
    Command.withDescription(
      "Set a variable's schema fields (type / required / description / max age) as a partial update. A missing name is created as a declared variable without a value. A declaration cannot be deleted from the CLI yet; downgrade a mistaken one with --optional so `maruhi run` proceeds",
    ),
  );

  const schemaImport = Command.make("import", schemaImportConfig, (values) =>
    Effect.gen(function* () {
      // The ceremony gate (the ceremony-family deny archetype of ADR-0016
      // decision 7) is judged **before any communication or file read**:
      // the per-variable interactive approval is the ceremony's core, and
      // no bulk --yes exists. Both layers — known-agent detection and the
      // non-interactive terminal — stop here (the judgment material goes
      // through the Stdio / AgentProfileRef services)
      yield* ensureImportCeremonyAllowed;
      const { file, ...flags } = values;
      // The file is read only on the client side (a value is wrapped in
      // Redacted right after parseEnvFile reads it — env-file.ts). When
      // unreadable, only the path is reported — never the content or the
      // OS error detail
      const content = yield* Effect.tryPromise({
        try: () => readFile(file, "utf8"),
        catch: () =>
          cliError(`Could not read ${displayText(file)} (check the path and permissions)`),
      });
      const context = yield* openEnvironment(flags);
      const summary = yield* schemaImportOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        resync: context.resync,
        floor: context.floorHandle,
        authorUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
        recipient: context.recipient,
        filePath: file,
        content,
      });
      if (summary.deletionOffered && !summary.deleted) {
        yield* logNote(
          `${displayText(file)} was kept. Once every variable it lists is declared, its last job is done — the signed schema (\`maruhi schema\`) becomes the source of truth`,
        );
      }
    }),
  ).pipe(
    Command.withDescription(
      "Import schema candidates from a .env or .env.example file with interactive per-variable approval (declares names without sending values; optionally pushes a value per variable)",
    ),
  );

  // export / verify-snapshot / lint share schema (display)'s
  // read-only, zero-value, keyless class (openMetadataEnvironment — works
  // under a MARUHI_TOKEN session = runnable from a user's CI). The
  // agent-gate does not apply (the permissive side — ADR-0016 decision
  // 7's scope is "value-displaying" commands only. Pinned by a test)
  const schemaExport = Command.make("export", schemaExportConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openMetadataEnvironment(values);
      yield* schemaExportOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        resync: context.resync,
        floor: context.floorHandle,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Print the environment's schema snapshot (a JSON Schema subset) to stdout. Commit it and check it in CI with `schema verify-snapshot`; the store stays the source of truth",
    ),
  );

  const schemaVerifySnapshot = Command.make(
    "verify-snapshot",
    schemaVerifySnapshotConfig,
    (values) =>
      Effect.gen(function* () {
        const { file, ...flags } = values;
        // The file is read before any network (a wrong path drops before a
        // round trip). Only the path is reported — never the content or
        // the OS error detail (same discipline as schema import)
        const fileContent = yield* Effect.tryPromise({
          try: () => readFile(file, "utf8"),
          catch: () =>
            cliError(`Could not read ${displayText(file)} (check the path and permissions)`),
        });
        const context = yield* openMetadataEnvironment(flags);
        yield* schemaVerifySnapshotOp({
          client: context.client,
          verified: context.verified,
          environmentId: context.environmentId,
          resync: context.resync,
          floor: context.floorHandle,
          filePath: file,
          fileContent,
        });
      }),
  ).pipe(
    Command.withDescription(
      "Verify a committed schema snapshot against the store and fail on any divergence (for CI; the store is the source of truth)",
    ),
  );

  const schemaLint = Command.make("lint", schemaLintConfig, (values) =>
    Effect.gen(function* () {
      // The scan precedes the network (a wrong path / an unreadable tree drops before a round trip)
      const scan = yield* scanPaths(values.paths);
      const context = yield* openMetadataEnvironment(values);
      yield* schemaLintOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        resync: context.resync,
        floor: context.floorHandle,
        scan,
        ignore: values.ignore,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Cross-check environment-variable references in source code against the declared schema (best-effort static scan; names only)",
    ),
  );

  // **bare `maruhi schema` = display** (design doc §1-1 — a handler-carrying parent like audit)
  const schema = Command.make("schema", schemaShowConfig, runSchemaShow).pipe(
    Command.withDescription(
      "Show the environment's declared variable schema (names, types, required, status, descriptions; no values). Bare `maruhi schema` shows; `schema set` writes",
    ),
    Command.withSubcommands([
      schemaSet,
      schemaImport,
      schemaExport,
      schemaVerifySnapshot,
      schemaLint,
    ]),
  );

  return schema;
}
