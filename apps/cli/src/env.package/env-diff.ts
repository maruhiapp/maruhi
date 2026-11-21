import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import type { CliServices } from "../context.ts";
import { countNoun, displayText, logWarnings } from "../display.ts";
import type { CliError } from "../errors.ts";
import type { FloorHandle, VerifiedVariableStatement } from "../floor-check.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import { pullVerifiedEnvironmentMetadata } from "../values.ts";

interface DiffTarget {
  readonly environmentId: EnvironmentId;
  readonly floor: FloorHandle;
}

type RequiredContract = "required" | "optional" | "none";

interface DiffSideEntry {
  readonly name: string;
  readonly declared: boolean;
  readonly required: RequiredContract;
}

interface ContractMismatch {
  readonly name: string;
  readonly first: { readonly declared: boolean; readonly required: RequiredContract };
  readonly second: { readonly declared: boolean; readonly required: RequiredContract };
}

interface EnvironmentDiff {
  readonly firstEnvironmentId: EnvironmentId;
  readonly secondEnvironmentId: EnvironmentId;
  readonly onlyInFirst: readonly DiffSideEntry[];
  readonly onlyInSecond: readonly DiffSideEntry[];
  readonly contractMismatches: readonly ContractMismatch[];
  readonly shared: number;
}

function sortedByName<T extends { readonly name: string }>(entries: Iterable<T>): readonly T[] {
  return [...entries].toSorted((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

function requiredOf(statement: VerifiedVariableStatement): RequiredContract {
  if (statement.schema === null) {
    return "none";
  }
  return statement.schema.required ? "required" : "optional";
}

function sideEntryOf(statement: VerifiedVariableStatement): DiffSideEntry {
  return {
    name: statement.name,
    declared: statement.status === "declared",
    required: requiredOf(statement),
  };
}

function statementsByName(
  variables: readonly VerifiedVariableStatement[],
): ReadonlyMap<string, VerifiedVariableStatement> {
  return new Map(variables.map((variable) => [variable.name, variable]));
}

export function reportEnvironmentWarnings(
  environmentId: EnvironmentId,
  warnings: readonly string[],
): Effect.Effect<void, CliError, CliIo> {
  return logWarnings(
    warnings.map((warning) => displayText(`environment ${environmentId}: ${warning}`)),
  );
}

export const envDiffOp = Effect.fn("env-diff.envDiffOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly first: DiffTarget;
  readonly second: DiffTarget;
  readonly commitHead: (verified: VerifiedProject) => Effect.Effect<void, CliError, CliServices>;
}): Effect.fn.Return<EnvironmentDiff, CliError, CliServices> {
  const first = yield* pullVerifiedEnvironmentMetadata({
    client: input.client,
    verified: input.verified,
    environmentId: input.first.environmentId,
    resync: input.resync,
    floor: input.first.floor,
  });
  yield* reportEnvironmentWarnings(input.first.environmentId, first.warnings);
  yield* input.commitHead(first.verified);
  const second = yield* pullVerifiedEnvironmentMetadata({
    client: input.client,
    verified: first.verified,
    environmentId: input.second.environmentId,
    resync: input.resync,
    floor: input.second.floor,
  });
  yield* reportEnvironmentWarnings(input.second.environmentId, second.warnings);
  yield* input.commitHead(second.verified);
  const firstByName = statementsByName(first.variables);
  const secondByName = statementsByName(second.variables);
  const contractMismatches: ContractMismatch[] = [];
  for (const [name, firstStatement] of firstByName) {
    const secondStatement = secondByName.get(name);
    if (secondStatement === undefined) {
      continue;
    }
    const firstSide = sideEntryOf(firstStatement);
    const secondSide = sideEntryOf(secondStatement);
    if (firstSide.declared !== secondSide.declared || firstSide.required !== secondSide.required) {
      contractMismatches.push({
        name,
        first: { declared: firstSide.declared, required: firstSide.required },
        second: { declared: secondSide.declared, required: secondSide.required },
      });
    }
  }
  return {
    firstEnvironmentId: input.first.environmentId,
    secondEnvironmentId: input.second.environmentId,
    onlyInFirst: sortedByName(
      [...firstByName.values()].filter((v) => !secondByName.has(v.name)).map(sideEntryOf),
    ),
    onlyInSecond: sortedByName(
      [...secondByName.values()].filter((v) => !firstByName.has(v.name)).map(sideEntryOf),
    ),
    contractMismatches: sortedByName(contractMismatches),
    shared: [...firstByName.keys()].filter((name) => secondByName.has(name)).length,
  };
});

function sideEntryLine(entry: DiffSideEntry): string {
  const notes = [
    ...(entry.required === "none" ? [] : [entry.required]),
    ...(entry.declared ? ["declared — no value set"] : []),
  ];
  const suffix = notes.length === 0 ? "" : ` (${notes.join(", ")})`;
  return `  ${displayText(entry.name)}${suffix}`;
}

function contractText(side: ContractMismatch["first"]): string {
  const required = side.required === "none" ? "no schema (layout v1)" : side.required;
  return side.declared ? `${required}, declared — no value set` : required;
}

export const reportEnvironmentDiff = Effect.fn("env-diff.reportEnvironmentDiff")(function* (
  diff: EnvironmentDiff,
): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
  const first = displayText(diff.firstEnvironmentId);
  const second = displayText(diff.secondEnvironmentId);
  yield* io.log(
    `Synced and verified: environment ${first} = ${countNoun(diff.onlyInFirst.length + diff.shared, "variable")} / environment ${second} = ${countNoun(diff.onlyInSecond.length + diff.shared, "variable")}`,
  );
  const sides = [
    { environmentId: first, entries: diff.onlyInFirst },
    { environmentId: second, entries: diff.onlyInSecond },
  ];
  for (const side of sides) {
    yield* io.log(`Variables only in environment ${side.environmentId}: ${side.entries.length}`);
    for (const entry of side.entries) {
      yield* io.log(sideEntryLine(entry));
    }
  }
  yield* io.log(
    `Variables in both with a differing schema contract: ${diff.contractMismatches.length}`,
  );
  for (const mismatch of diff.contractMismatches) {
    yield* io.log(
      `  ${displayText(mismatch.name)} — ${first}: ${contractText(mismatch.first)} / ${second}: ${contractText(mismatch.second)}`,
    );
  }
  yield* io.log(
    `Variables in both: ${diff.shared} (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)`,
  );
  const advice =
    diff.onlyInFirst.length + diff.onlyInSecond.length > 0
      ? "For differences you cannot explain, run this again to confirm before filling them in with a push (a push is an irreversible chain append and may overwrite a newer value with an older one)"
      : "Before treating zero differences as proof the environments are in sync, run this again to confirm";
  yield* logNote(
    `the two environments are read sequentially, not atomically (there is no API that reads two environments at once). If another member pushes or deletes during the run, differences may appear that do not exist, and real differences may not appear — ${advice}`,
  );
});
