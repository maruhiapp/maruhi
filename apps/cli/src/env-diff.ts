// The cross-environment parity check (`maruhi env diff`).
//
// For two environments in the same project it compares **the set of
// variable names** and **the schema contract (required, and the
// set / declared state — the required axis of design doc §1-5)**, and
// reports names present on only one side and names present on both but
// with disagreeing contracts (detecting "forgot to put it in prod" or
// "staging has no required declaration" without looking at a single
// value). description is not shown in the diff output (the §2
// consumption-point discipline — the same line as fail-fast and lint).
//
// Neither values nor DEKs are fetched: the input is only a §12-7
// metadata-only pull, and no plaintext value is ever materialized in
// memory. The server does not record `var.read` on this endpoint
// (AUDIT_SPEC §3.3) — that discipline protects the input purity of the
// rotation-needed detection of AUDIT_SPEC §4, so diff does not add
// records either.
//
// The comparison is done on **verified statements' name** (only what
// passed §6.3 is trusted — §12-2). The matching rule is AUTH_SPEC §12-1's
// byte-exact, case-sensitive comparison (POSIX environment-variable-name
// semantics), and matching variable names across environments by the
// plaintext metadata names is per CRYPTO_SPEC §4. Deleted (tombstone)
// variables are out of scope; only the latest active statement is read.
//
// **A name present on both means nothing more than "the name matches"**.
// Whether the values match cannot be known without decrypting, and this
// mechanism fundamentally never touches that — the report says so
// explicitly (reading it as "in sync" would make the user believe an
// undetected discrepancy was detected).
//
// **Specimen skew (never claimed as checked)**: the two environments are
// read **sequentially** in two pulls. Because there is no API that reads
// two environments at once, if another member's push slips in between the
// first and second read, that variable temporarily appears on only one
// side = **a phantom difference**. There is a reverse direction too: if a
// variable is deleted from one side after the first is read, it is
// reported as present on both and ends with zero differences = **a missed
// real difference**. What is aligned here is the chain view used for
// verification, not the simultaneity of the variable sets (the former
// prevents §6.3 verification from running against separate histories; the
// latter cannot be guaranteed). A user's "fix" based on a phantom
// difference is a push — an irreversible append to the chain, and one
// that may overwrite a newer value with an older one — and the missed
// side reads as "in sync". Since either conclusion can be overturned, the
// caveat is attached **always, regardless of whether differences exist**
// (reportEnvironmentDiff).
//
// AI-agent detection (agent.ts) is not applied: agent.ts's line is
// "operations that display values on the terminal", and variable names
// are **plaintext metadata by design** (CRYPTO_SPEC §4 — name secrecy is
// unresolved #3), not values. `maruhi pull` without `--show` already
// displays the same listing (agent determination is only under `--show`).
//
// However, "narrower disclosure than pull" cannot be claimed — since it
// does not require the master key, on a device without a keychain (via
// MARUHI_TOKEN — session.ts) pull fails at loadMasterKeys while this
// command prints both environments' variable-name listings. **It is the
// first command to emit variable names under that credential**. The line
// itself does not change (the disclosure boundary is the token; the
// server returns pullMetadata to anyone with read permission — whether a
// local key exists is uninvolved), but treating names like values would
// mean re-examining agent.ts's line itself, so the judgment is recorded
// here rather than swallowed.

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import type { CliServices } from "./context.ts";
import { countNoun, displayText, logWarnings } from "./display.ts";
import type { CliError } from "./errors.ts";
import type { FloorHandle, VerifiedVariableStatement } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import { pullVerifiedEnvironmentMetadata } from "./values.ts";

/** One environment under comparison. The floor is used for §6.3's meta-level checks (not committed). */
export interface DiffTarget {
  readonly environmentId: EnvironmentId;
  readonly floor: FloorHandle;
}

/**
 * One variable's required contract (derived only from the verified
 * statement's schema field — server declarations are not used, §14.2-8).
 * `none` = no schema field (layout v1).
 */
export type RequiredContract = "required" | "optional" | "none";

/** One variable present on only one side (name, state, required — description is not carried, §2). */
export interface DiffSideEntry {
  readonly name: string;
  /** true = declared (no value). */
  readonly declared: boolean;
  readonly required: RequiredContract;
}

/** Among the names present on both sides, those whose declared contract (required / state) disagrees. */
export interface ContractMismatch {
  readonly name: string;
  readonly first: { readonly declared: boolean; readonly required: RequiredContract };
  readonly second: { readonly declared: boolean; readonly required: RequiredContract };
}

/** The result of the variable-name set comparison (name-sorted differences and counts). */
export interface EnvironmentDiff {
  readonly firstEnvironmentId: EnvironmentId;
  readonly secondEnvironmentId: EnvironmentId;
  /** Variables only in the first (name-sorted). */
  readonly onlyInFirst: readonly DiffSideEntry[];
  /** Variables only in the second (name-sorted). */
  readonly onlyInSecond: readonly DiffSideEntry[];
  /**
   * Among the names present on both, those whose required contract or
   * state (set / declared) disagrees (the required axis of §1-5 — the
   * decision material is only both environments' verified statements).
   */
  readonly contractMismatches: readonly ContractMismatch[];
  /** The number of names present on both. **Does not imply the values match** (they are never decrypted). */
  readonly shared: number;
}

/**
 * The name ordering is ascending by **UTF-16 code unit** (the default
 * comparison). localeCompare is not used because the order varies with
 * the runtime's locale — if comparing the same two environments printed
 * in different orders on different terminals, the output itself could no
 * longer be diffed.
 */
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

/**
 * Verified variable statements (a mix of active + declared — §12-7) →
 * name → statement map. declared is included in the comparison as "an
 * existing variable name" (the S3 ruling — declared is a first-class
 * variable, §4.2; the presence of a value is shown as a note). A
 * same-name collision within one environment is already refused by
 * §6.3's verification (values-verify.ts's checkVerifiedNames), so folding into
 * the map here loses no fact.
 */
function statementsByName(
  variables: readonly VerifiedVariableStatement[],
): ReadonlyMap<string, VerifiedVariableStatement> {
  return new Map(variables.map((variable) => [variable.name, variable]));
}

/**
 * Emits one environment's §12-1 SHOULD warnings to stderr, labelled with the
 * environment id.
 *
 * **Emitted immediately per pull**: so the first pull's warnings are not
 * dropped on a run where the second pull fails (the same discipline as
 * env-rotate's "collected warnings are always emitted even on a failure
 * path").
 *
 * The two environments' warnings can be the same line (variable_id is
 * unique **within an environment**, so an identical warning can fire for
 * a different variable in the other environment). Folding by set would
 * silently drop one fact, so they are labelled by environment ID instead
 * of deduplicated.
 *
 * The assembled line goes through displayText whole — the environment ID
 * is not necessarily verified since `EnvironmentId` is not branded, and a
 * future producer of the warning body is not necessarily neutralized
 * (displayText is idempotent, so double application does not corrupt).
 */
export function reportEnvironmentWarnings(
  environmentId: EnvironmentId,
  warnings: readonly string[],
): Effect.Effect<void, CliError, CliIo> {
  return logWarnings(
    warnings.map((warning) => displayText(`environment ${environmentId}: ${warning}`)),
  );
}

/**
 * Compares the variable **names** of two environments in one project, using
 * only metadata pulls (no values, no DEKs, no `var.read`).
 *
 * The second pull is passed **the view the first returned**: a metadata
 * pull may advance the view via a bounded resync on a future head
 * (§6.3-2b), and reusing the original view would compare the two
 * environments as verified against **separate histories**.
 */
export function envDiffOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  /** The bounded resync on a future head (each pull uses it once). */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly first: DiffTarget;
  readonly second: DiffTarget;
  /**
   * Recording the verified chain head. **Called per pull**: called only
   * once at the end, a run whose second pull fails would drop the
   * advancement the first pull's bounded resync established (pull / push
   * write the same head inside each response's accept).
   */
  readonly commitHead: (verified: VerifiedProject) => Effect.Effect<void, CliError, CliServices>;
}): Effect.Effect<EnvironmentDiff, CliError, CliServices> {
  return Effect.gen(function* () {
    const first = yield* pullVerifiedEnvironmentMetadata({
      client: input.client,
      verified: input.verified,
      environmentId: input.first.environmentId,
      resync: input.resync,
      floor: input.first.floor,
    });
    // Warnings then head recording, in that order (neither depends on the second pull's success)
    yield* reportEnvironmentWarnings(input.first.environmentId, first.warnings);
    yield* input.commitHead(first.verified);
    const second = yield* pullVerifiedEnvironmentMetadata({
      client: input.client,
      // Carries over the view the first's verification used (it may have advanced)
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
      if (
        firstSide.declared !== secondSide.declared ||
        firstSide.required !== secondSide.required
      ) {
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
}

/**
 * The display annotation for a variable present on only one side (the
 * §1-5 required axis + a declared note). Output is name, state, and
 * required only — **description is not shown** (the §2 consumption-point
 * discipline: the same line as fail-fast errors and lint reports; the
 * diff output also flows to logs / CI). required satisfaction and
 * declaration come from signed statements, but display treats them as
 * declared and does not use the word "verified" (the §14.3 display
 * discipline).
 */
function sideEntryLine(entry: DiffSideEntry): string {
  const notes = [
    ...(entry.required === "none" ? [] : [entry.required]),
    ...(entry.declared ? ["declared — no value set"] : []),
  ];
  const suffix = notes.length === 0 ? "" : ` (${notes.join(", ")})`;
  return `  ${displayText(entry.name)}${suffix}`;
}

/** Displaying one side of a contract mismatch (required / optional / no schema + a declared note). */
function contractText(side: ContractMismatch["first"]): string {
  const required = side.required === "none" ? "no schema (layout v1)" : side.required;
  return side.declared ? `${required}, declared — no value set` : required;
}

/**
 * Reporting the diff. The listing goes to stdout (the command's output)
 * and warnings to stderr (logWarnings) — the "stdout is only the
 * command's output" discipline.
 *
 * Every string emitted to the terminal **is neutralized by this
 * function** (warnings are handled by reportEnvironmentWarnings under the
 * same discipline). A variable name is plaintext metadata another member
 * wrote and may carry ANSI / BEL (handled the same as pull's
 * formatPulledLine), and since `EnvironmentId` is not branded, the type
 * cannot guarantee the environment ID is verified either.
 */
export function reportEnvironmentDiff(diff: EnvironmentDiff): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
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
      // The count is printed even at 0 names (the output's shape does not vary between runs)
      yield* io.log(`Variables only in environment ${side.environmentId}: ${side.entries.length}`);
      for (const entry of side.entries) {
        yield* io.log(sideEntryLine(entry));
      }
    }
    // The required axis (§1-5): even for names present on both, a
    // disagreeing declared contract (required / set / declared) is shown.
    // The count line is printed even at 0 (same "the output's shape does
    // not vary between runs" discipline as above)
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
    // The specimen-skew caveat is **always** printed (stderr — it is
    // advice, not the command's output, so it is not mixed into the
    // stdout diff listing). Going silent at zero differences would hide
    // **skew's most dangerous direction**: if a variable is deleted from
    // one side after the first is read, it is reported as present on both
    // and ends at zero differences = a real difference reads as "in
    // sync". Only the advice follows the conclusion
    const advice =
      diff.onlyInFirst.length + diff.onlyInSecond.length > 0
        ? "For differences you cannot explain, run this again to confirm before filling them in with a push (a push is an irreversible chain append and may overwrite a newer value with an older one)"
        : "Before treating zero differences as proof the environments are in sync, run this again to confirm";
    yield* logNote(
      `the two environments are read sequentially, not atomically (there is no API that reads two environments at once). If another member pushes or deletes during the run, differences may appear that do not exist, and real differences may not appear — ${advice}`,
    );
  });
}
