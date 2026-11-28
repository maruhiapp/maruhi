import { readFile } from "node:fs/promises";

import { MAX_META_MAX_AGE_DAYS, type MetaVarType } from "@maruhi/crypto";
import { Effect } from "effect";
import { Argument, Command, CliError as EffectCliError, Flag } from "effect/cli";

import type { CliServices } from "../cli.ts";
import {
  NonBlank,
  commonFlags,
  invalidFlagCombination,
  singleFlag,
  singleValued,
} from "../commands/flags.ts";
import { openEnvironment, openMetadataEnvironment } from "../commands/lazy.ts";
import { displayText, logWarnings } from "../display.ts";
import { CliError, cliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import type { FieldUpdate, SchemaFieldUpdates, SchemaSetSummary } from "./schema.ts";

/** @public */
export const schemaShowConfig = { ...commonFlags() };

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

/** @public */
export const schemaImportConfig = {
  ...commonFlags(),
  file: Argument.String("file").pipe(
    Argument.withDescription(
      "Path to a .env or .env.example file to read locally (values are observed for type inference only; never sent unless you explicitly choose to push one)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** @public */
export const schemaExportConfig = { ...commonFlags() };

/** @public */
export const schemaVerifySnapshotConfig = {
  ...commonFlags(),
  file: Argument.String("file").pipe(
    Argument.withDescription(
      "Path to the committed snapshot file (generate with `maruhi schema export`)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** @public */
export const schemaLintConfig = {
  ...commonFlags(),
  ignore: Flag.String("ignore").pipe(
    Flag.withDescription(
      "Environment-variable name to exclude from the undeclared check (repeatable; for runtime variables not managed by maruhi, e.g. NODE_ENV)",
    ),
    Flag.withSchema(NonBlank),
    Flag.atLeast(0),
  ),
  path: Argument.String("path").pipe(
    Argument.withDescription("File or directory to scan for environment-variable references"),
    Argument.atLeast(1),
  ),
};

const runSchemaShow = Effect.fn("schema-command.runSchemaShow")(function* (values: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
}): Effect.fn.Return<void, CliError, CliServices> {
  const { schemaShowOp } = yield* Effect.promise(() =>
    import("./schema.ts").then((m) => ({ schemaShowOp: m.schemaShowOp })),
  );

  const context = yield* openMetadataEnvironment(values);
  yield* schemaShowOp({
    client: context.client,
    verified: context.verified,
    environmentId: context.environmentId,
    resync: context.resync,
    floor: context.floorHandle,
  });
});

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

function rejectContradictorySchemaFlags(values: {
  readonly required: boolean;
  readonly optional: boolean;
  readonly description?: string | undefined;
  readonly "clear-description": boolean;
}): Effect.Effect<void, EffectCliError.ValidationError> {
  if (values.required && values.optional) {
    return invalidFlagCombination(
      "--required and --optional are mutually exclusive (specify at most one)",
    );
  }
  if (values.description !== undefined && values["clear-description"]) {
    return invalidFlagCombination("--description and --clear-description are mutually exclusive");
  }
  return Effect.void;
}

const parseSchemaFieldUpdates = Effect.fn("schema-command.parseSchemaFieldUpdates")(
  function* (values: {
    readonly type?: string | undefined;
    readonly required: boolean;
    readonly optional: boolean;
    readonly description?: string | undefined;
    readonly "clear-description": boolean;
    readonly "max-age"?: string | undefined;
  }): Effect.fn.Return<SchemaFieldUpdates, CliError> {
    const varType = yield* parseSchemaTypeFlag(values.type);
    const maxAgeDays = yield* parseMaxAgeFlag(values["max-age"]);
    const required: FieldUpdate<boolean> = values.required
      ? { kind: "set", value: true }
      : values.optional
        ? { kind: "set", value: false }
        : { kind: "keep" };
    const description: FieldUpdate<string> = values["clear-description"]
      ? { kind: "set", value: "" }
      : values.description !== undefined
        ? { kind: "set", value: values.description }
        : { kind: "keep" };
    return { varType, required, description, maxAgeDays };
  },
);

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
  const schemaSet = Command.make(
    "set",
    schemaSetConfig,
    Effect.fn("schema-command.schemaSet")(function* (values) {
      const { ensureEntropyAcknowledged, schemaSetOp } = yield* Effect.promise(() =>
        import("./schema.ts").then((m) => ({
          ensureEntropyAcknowledged: m.ensureEntropyAcknowledged,
          schemaSetOp: m.schemaSetOp,
        })),
      );

      const io = yield* CliIo;
      const updates = yield* parseSchemaFieldUpdates(values);
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
    Command.validate((values) => rejectContradictorySchemaFlags(values)),
  );

  const schemaImport = Command.make(
    "import",
    schemaImportConfig,
    Effect.fn("schema-command.schemaImport")(function* (values) {
      const { ensureImportCeremonyAllowed, schemaImportOp } = yield* Effect.promise(() =>
        import("./schema-import.ts").then((m) => ({
          ensureImportCeremonyAllowed: m.ensureImportCeremonyAllowed,
          schemaImportOp: m.schemaImportOp,
        })),
      );

      yield* ensureImportCeremonyAllowed;
      const { file, ...flags } = values;
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

  const schemaExport = Command.make(
    "export",
    schemaExportConfig,
    Effect.fn("schema-command.schemaExport")(function* (values) {
      const { schemaExportOp } = yield* Effect.promise(() =>
        import("./schema-snapshot.ts").then((m) => ({ schemaExportOp: m.schemaExportOp })),
      );

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
    Effect.fn("schema-command.schemaVerifySnapshot")(function* (values) {
      const { schemaVerifySnapshotOp } = yield* Effect.promise(() =>
        import("./schema-snapshot.ts").then((m) => ({
          schemaVerifySnapshotOp: m.schemaVerifySnapshotOp,
        })),
      );

      const { file, ...flags } = values;
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

  const schemaLint = Command.make(
    "lint",
    schemaLintConfig,
    Effect.fn("schema-command.schemaLint")(function* (values) {
      const { scanPaths, schemaLintOp } = yield* Effect.promise(() =>
        import("./schema-lint.ts").then((m) => ({
          scanPaths: m.scanPaths,
          schemaLintOp: m.schemaLintOp,
        })),
      );

      const scan = yield* scanPaths(values.path);
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
