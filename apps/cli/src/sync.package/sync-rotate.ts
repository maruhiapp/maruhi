// Receipt advancement driven by `maruhi env rotate --config`
// (integration-options.md §3 supplement 14 M1).
//
// An epoch rotation (CRYPTO_SPEC §7 / §4.1) re-encrypts the
// current value **as a new version** (the plaintext is
// unchanged). Since the receipt (sync-receipt.ts) only carries
// the version, `maruhi sync plan` after a rotation shows every
// variable as changed, and the next apply rewrites the same
// plaintext — harmless but wasteful, and on production it incurs
// the `--yes` ceremony. The only party that knows the plaintext
// is unchanged is **the rotating executor's CLI**, so inside
// that run the receipt is advanced to the new version. No crypto
// is added: writing the receipt is storeReceipt = a §4.1-signed
// ordinary push (the executor's master key).
//
// A receipt may advance only for a variable whose re-encryption
// **this run completed** (RotationSummary.written) AND whose
// **immediately previous version** the receipt pointed at.
// Advancing a lagging receipt (where an older plaintext is what
// the target holds) would hide an unsynced diff, so it is not
// advanced. `alreadyCurrent` (a concurrent push — the plaintext
// may have changed), incomplete ones, and names absent from the
// receipt (unsynced) are not advanced either — a variable the
// judgment is unsure about falls toward "the next apply
// harmlessly rewrites".
//
// This is cleanup, not part of the rotation: a failure here
// (communication, authority, conflict — in the re-sync, the
// receipt read, or the write alike) stays a warning and does not
// change the rotation's own exit code (same as sync-plan.ts's
// saveReceipt). **The exception is evidence**
// (`CliError.evidence` — floor violation, chain replacement,
// equivocation): a contradiction between properly signed data is
// not the kind of failure "the next apply rewrites", and folding
// it into a warning would hide tamper evidence behind the wrong
// guidance "just re-apply". Evidence alone passes through as a
// failure (same discipline as env-rotate-push.ts's re-scan). It talks
// only to the maruhi server and never touches the sync target
// (vendor API / CLI). What appears in the output is only the
// target name, counts, versions, and variable names
// (displayText).

import { type EnvironmentId, type ProjectId, type UserId } from "@maruhi/core";
import { Clock, Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import type { DekRecipient } from "../deks.ts";
import { countNoun, displayText, logWarnings } from "../display.ts";
import type { ReencryptedVariable } from "../env-rotate.ts";
import { asCleanupOutcome, type CliError, usageError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
import { CliIo } from "../io.ts";
import { logWarning } from "../notice.ts";
import type { SyncConfig, SyncTarget } from "./sync-config.ts";
import type { SyncReceipt } from "./sync-receipt.ts";

// P-6: chain-sync.ts / sync-receipt.ts (the verified-chain and receipt
// machinery) are imported lazily inside the bodies that use them —
// index.ts re-exports this file, so an eager import here would be paid by
// every CLI run (see commands/shared.ts's P-6 note).

/**
 * Collates the config's `project` against the project actually
 * rotated (a disagreement is a write-up error). Compared against
 * the resolved project ID regardless of `--project` — call it
 * **before** the rotation, closing the shape where an epoch
 * advances under a different project's config.
 */
export function checkRotateConfigProject(
  config: SyncConfig,
  projectId: ProjectId,
): Effect.Effect<void, CliError> {
  if (config.projectId !== undefined && config.projectId !== projectId) {
    return Effect.fail(
      usageError(
        "The sync config belongs to a different project (its `project` does not match the project being rotated)",
      ),
    );
  }
  return Effect.void;
}

/** The targets syncing from the rotated environment (in config order). */
function targetsSyncedFrom(
  config: SyncConfig,
  environmentId: EnvironmentId,
): readonly SyncTarget[] {
  return [...config.targets.values()].filter((target) => target.environment === environmentId);
}

/** The receipt-advancement judgment's result (for one target). */
interface AdvancedReceipt {
  readonly receipt: SyncReceipt;
  /** Names advanced to the new version because the receipt pointed at the previous version. */
  readonly advanced: readonly string[];
  /** Names in the receipt that did not point at the previous version (lagging or a different lineage — not advanced). */
  readonly behind: readonly string[];
}

/**
 * Advances a receipt to the re-encrypted versions: a variable moves only when
 * the receipt points at the version just before the accepted write (that
 * version and the new one carry the same plaintext). Names the receipt does
 * not know stay unsynced, and a receipt that was behind stays behind.
 */
function advanceReceipt(
  previous: SyncReceipt,
  written: readonly ReencryptedVariable[],
  syncedAt: string,
): AdvancedReceipt {
  const variables: Record<string, number> = Object.assign(
    Object.create(null) as Record<string, number>,
    previous.variables,
  );
  const advanced: string[] = [];
  const behind: string[] = [];
  for (const entry of written) {
    const delivered = variables[entry.name];
    if (delivered === undefined) {
      continue;
    }
    if (delivered === entry.version - 1) {
      variables[entry.name] = entry.version;
      advanced.push(entry.name);
    } else {
      behind.push(entry.name);
    }
  }
  return {
    receipt: { ...previous, syncedAt, variables },
    advanced: advanced.toSorted(),
    behind: behind.toSorted(),
  };
}

interface AdvanceReceiptsInput {
  readonly client: MaruhiClient;
  /** The verified view from before the rotation (the reference for checking the re-synced chain is its extension). */
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  /**
   * The re-sync (a full chain re-verification). Since the
   * rotation advanced the chain, cleanup re-fetches with this
   * and starts from a verified view confirmed to be an
   * **extension** of `verified` (the discipline of starting from
   * the advanced view). Communication failures fold into a
   * warning inside the cleanup; a verification refusal
   * (evidence) passes through (only evidence may change the
   * rotation's exit code).
   */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly config: SyncConfig;
  /** The rotated environment (only targets syncing from this environment are covered). */
  readonly environmentId: EnvironmentId;
  readonly written: readonly ReencryptedVariable[];
  /** The receipt environment's floor handle (when it is the same environment that was rotated, the rotate's one is shared). */
  readonly receiptsFloor: FloorHandle;
  readonly writerUserId: UserId;
  readonly signingKey: CryptoKey;
}

/** One target's result (for display). */
type TargetOutcome =
  | { readonly kind: "no-receipt" }
  | { readonly kind: "nothing-to-advance"; readonly behind: readonly string[] }
  | { readonly kind: "advanced"; readonly version: number; readonly result: AdvancedReceipt };

/** Reads one target's receipt and writes only what can be advanced. A failure comes back as a typed error. */
const advanceTarget = Effect.fn("sync-rotate.advanceTarget")(function* (
  input: AdvanceReceiptsInput,
  target: SyncTarget,
  verified: VerifiedProject,
): Effect.fn.Return<
  { readonly outcome: TargetOutcome; readonly verified: VerifiedProject },
  CliError,
  CliIo
> {
  const { loadReceipt, receiptVersionWarning, storeReceipt } = yield* Effect.promise(
    () => import("./sync-receipt.ts"),
  );
  const receiptsEnvironment = input.config.receiptsEnvironment;
  const loaded = yield* loadReceipt({
    client: input.client,
    verified,
    environmentId: receiptsEnvironment,
    recipient: input.recipient,
    resync: input.resync,
    floor: input.receiptsFloor,
    target: target.name,
    preset: target.preset.id,
  });
  yield* logWarnings(loaded.warnings);
  if (loaded.receipt === null) {
    // Before the first sync = nothing to advance (skipped quietly — plan says everything is new)
    return { outcome: { kind: "no-receipt" }, verified: loaded.verified };
  }
  const syncedAtMs = yield* Clock.currentTimeMillis;
  const result = advanceReceipt(loaded.receipt, input.written, new Date(syncedAtMs).toISOString());
  if (result.advanced.length === 0) {
    // Nothing is written when the content does not change (does not consume a version)
    return {
      outcome: { kind: "nothing-to-advance", behind: result.behind },
      verified: loaded.verified,
    };
  }
  const stored = yield* storeReceipt({
    client: input.client,
    verified: loaded.verified,
    environmentId: receiptsEnvironment,
    recipient: input.recipient,
    resync: input.resync,
    floor: input.receiptsFloor,
    writerUserId: input.writerUserId,
    signingKey: input.signingKey,
    receipt: result.receipt,
  });
  yield* logWarnings(stored.warnings);
  const warning = receiptVersionWarning({
    target: target.name,
    environmentId: receiptsEnvironment,
    variableVersion: stored.version,
  });
  if (warning !== null) {
    yield* logWarning(warning);
  }
  // The receipt's push hands the advanced view (the pull may have advanced it) to the next step
  return {
    outcome: { kind: "advanced", version: stored.version, result },
    verified: loaded.verified,
  };
});

function behindNote(behind: readonly string[]): string {
  return behind.length === 0
    ? ""
    : `; ${countNoun(behind.length, "variable")} left as delivered (${behind.map(displayText).join(", ")}: the receipt was already behind before the rotation, so the next \`maruhi sync plan\` shows them as pending)`;
}

const reportTarget = Effect.fn("sync-rotate.reportTarget")(function* (
  target: SyncTarget,
  outcome: TargetOutcome,
  receiptsEnvironment: string,
): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
  const { receiptVariableName } = yield* Effect.promise(() => import("./sync-receipt.ts"));
  switch (outcome.kind) {
    case "no-receipt":
      // No receipt = never synced once. Says nothing
      return;
    case "nothing-to-advance":
      if (outcome.behind.length > 0) {
        yield* io.log(
          `Receipt for target ${target.name} not advanced: ${countNoun(outcome.behind.length, "variable")} left as delivered (${outcome.behind.map(displayText).join(", ")}: the receipt was already behind before the rotation, so the next \`maruhi sync plan\` shows them as pending)`,
        );
      }
      return;
    case "advanced":
      yield* io.log(
        `Advanced the receipt for target ${target.name} to the re-encrypted versions of ${countNoun(outcome.result.advanced.length, "variable")} (saved as version ${outcome.version} of ${displayText(receiptVariableName(target.name))} in environment ${displayText(receiptsEnvironment)})${behindNote(outcome.result.behind)}`,
      );
      return;
  }
});

/**
 * Advances the receipts of every target synced from the rotated environment
 * to the versions this rotation wrote. A failure on one target is a warning
 * (the rotation is already done; the next apply rewrites the same plaintext),
 * and the remaining targets are still processed. Only evidence (a floor or
 * chain verification rejection) fails the command.
 */
export const advanceReceiptsAfterRotation = Effect.fn("sync-rotate.advanceReceiptsAfterRotation")(
  function* (input: AdvanceReceiptsInput): Effect.fn.Return<void, CliError, CliIo> {
    const io = yield* CliIo;
    if (input.written.length === 0) {
      // Nothing was re-encrypted (check-only or could not push) = nothing to advance
      return;
    }
    const targets = targetsSyncedFrom(input.config, input.environmentId);
    if (targets.length === 0) {
      yield* io.log(
        `No sync target in the config is synced from environment ${displayText(input.environmentId)}, so no receipt was advanced`,
      );
      return;
    }
    // A re-sync failure is also a cleanup failure: the rotation
    // is already done, so keep it a warning (failing it outside
    // the envelope would turn the exit code into 1 after a
    // successful report)
    const { resyncExtended } = yield* Effect.promise(() => import("../chain-sync.ts"));
    const synced = yield* asCleanupOutcome(resyncExtended(input.resync, input.verified));
    if (synced.kind === "failed") {
      yield* logWarning(
        `the rotation is done, but the receipts could not be advanced because the chain could not be re-verified (${synced.error.message}). The next \`maruhi sync plan\` shows the re-encrypted variables as pending; applying again overwrites them with the same plaintext`,
      );
      return;
    }
    let verified = synced.value;
    for (const target of targets) {
      const attempt = yield* asCleanupOutcome(advanceTarget(input, target, verified));
      if (attempt.kind === "failed") {
        // One target's failure does not stop the rest. The exit code is unchanged either (cleanup)
        yield* logWarning(
          `the rotation is done, but the receipt for target ${target.name} could not be advanced (${attempt.error.message}). The next \`maruhi sync plan ${target.name}\` shows the re-encrypted variables as pending; applying again overwrites them with the same plaintext`,
        );
        continue;
      }
      verified = attempt.value.verified;
      yield* reportTarget(target, attempt.value.outcome, input.config.receiptsEnvironment);
    }
  },
);
