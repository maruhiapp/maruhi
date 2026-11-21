import { type EnvironmentId, type ProjectId, type UserId } from "@maruhi/core";
import { Clock, Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import type { DekRecipient } from "../deks.ts";
import { countNoun, displayText, logWarnings } from "../display.ts";
import type { ReencryptedVariable } from "../env.package/index.ts";
import { asCleanupOutcome, type CliError, usageError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
import { CliIo } from "../io.ts";
import { logWarning } from "../notice.ts";
import type { SyncConfig, SyncTarget } from "./sync-config.ts";
import type { SyncReceipt } from "./sync-receipt.ts";

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

function targetsSyncedFrom(
  config: SyncConfig,
  environmentId: EnvironmentId,
): readonly SyncTarget[] {
  return [...config.targets.values()].filter((target) => target.environment === environmentId);
}

interface AdvancedReceipt {
  readonly receipt: SyncReceipt;
  readonly advanced: readonly string[];
  readonly behind: readonly string[];
}

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
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly config: SyncConfig;
  readonly environmentId: EnvironmentId;
  readonly written: readonly ReencryptedVariable[];
  readonly receiptsFloor: FloorHandle;
  readonly writerUserId: UserId;
  readonly signingKey: CryptoKey;
}

type TargetOutcome =
  | { readonly kind: "no-receipt" }
  | { readonly kind: "nothing-to-advance"; readonly behind: readonly string[] }
  | { readonly kind: "advanced"; readonly version: number; readonly result: AdvancedReceipt };

const advanceTarget = Effect.fn("sync-rotate.advanceTarget")(function* (
  input: AdvanceReceiptsInput,
  target: SyncTarget,
  verified: VerifiedProject,
): Effect.fn.Return<
  { readonly outcome: TargetOutcome; readonly verified: VerifiedProject },
  CliError,
  CliIo
> {
  const { loadReceipt, receiptVersionWarning, storeReceipt } = yield* Effect.promise(() =>
    import("./sync-receipt.ts").then((m) => ({
      loadReceipt: m.loadReceipt,
      receiptVersionWarning: m.receiptVersionWarning,
      storeReceipt: m.storeReceipt,
    })),
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
    return { outcome: { kind: "no-receipt" }, verified: loaded.verified };
  }
  const syncedAtMs = yield* Clock.currentTimeMillis;
  const result = advanceReceipt(loaded.receipt, input.written, new Date(syncedAtMs).toISOString());
  if (result.advanced.length === 0) {
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
  const { receiptVariableName } = yield* Effect.promise(() =>
    import("./sync-receipt.ts").then((m) => ({ receiptVariableName: m.receiptVariableName })),
  );
  switch (outcome.kind) {
    case "no-receipt":
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

export const advanceReceiptsAfterRotation = Effect.fn("sync-rotate.advanceReceiptsAfterRotation")(
  function* (input: AdvanceReceiptsInput): Effect.fn.Return<void, CliError, CliIo> {
    const io = yield* CliIo;
    if (input.written.length === 0) {
      return;
    }
    const targets = targetsSyncedFrom(input.config, input.environmentId);
    if (targets.length === 0) {
      yield* io.log(
        `No sync target in the config is synced from environment ${displayText(input.environmentId)}, so no receipt was advanced`,
      );
      return;
    }
    const { resyncExtended } = yield* Effect.promise(() =>
      import("../chain-sync.ts").then((m) => ({ resyncExtended: m.resyncExtended })),
    );
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
