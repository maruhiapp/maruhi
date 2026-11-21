import { type EnvironmentId, type UserId } from "@maruhi/core";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import type { DekRecipient } from "../deks.ts";
import { decodeValueText, displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
import { parseJsonRecord } from "../json-record.ts";
import { pullVariables } from "../pull.ts";
import { pushVariable } from "../push.package/index.ts";
import { PRESET_IDS, type PresetId } from "./sync-types.ts";

export interface SyncReceipt {
  readonly version: 1;
  readonly target: string;
  readonly preset: PresetId;
  readonly syncedAt: string;
  readonly variables: Readonly<Record<string, number>>;
}

const RECEIPT_VERSION_LIMIT = 1_000;
const RECEIPT_VERSION_WARN_AT = 900;

export function receiptVariableName(target: string): string {
  return `sync-receipt:${target}`;
}

export function decodeReceipt(text: string, expectedTarget: string): SyncReceipt | string {
  const record = parseJsonRecord(text);
  if (typeof record === "string") {
    return record;
  }
  if (record["version"] !== 1) {
    return "unsupported receipt version (expected 1)";
  }
  if (record["target"] !== expectedTarget) {
    return "the receipt names a different target";
  }
  const preset = record["preset"];
  if (typeof preset !== "string" || !PRESET_IDS.includes(preset as PresetId)) {
    return "unknown preset";
  }
  const syncedAt = record["syncedAt"];
  if (typeof syncedAt !== "string") {
    return "syncedAt must be a string";
  }
  const variablesRaw = record["variables"];
  if (typeof variablesRaw !== "object" || variablesRaw === null || Array.isArray(variablesRaw)) {
    return "variables must be an object of { name: version }";
  }
  const variables: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const [name, version] of Object.entries(variablesRaw)) {
    if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) {
      return "variables must map names to positive integer versions";
    }
    variables[name] = version;
  }
  return { version: 1, target: expectedTarget, preset: preset as PresetId, syncedAt, variables };
}

export function encodeReceipt(receipt: SyncReceipt): Uint8Array {
  const variables: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const name of Object.keys(receipt.variables).toSorted()) {
    variables[name] = receipt.variables[name] as number;
  }
  return new TextEncoder().encode(
    JSON.stringify({
      version: 1,
      target: receipt.target,
      preset: receipt.preset,
      syncedAt: receipt.syncedAt,
      variables,
    }),
  );
}

export interface LoadedReceipt {
  readonly receipt: SyncReceipt | null;
  readonly variableVersion: number;
  readonly verified: VerifiedProject;
  readonly warnings: readonly string[];
}

export const loadReceipt = Effect.fn("sync-receipt.loadReceipt")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly target: string;
  readonly preset: PresetId;
}): Effect.fn.Return<LoadedReceipt, CliError> {
  const name = receiptVariableName(input.target);
  const pulled = yield* pullVariables({ ...input, select: (n) => n === name });
  const variable = pulled.variables.find((entry) => entry.name === name);
  if (variable === undefined) {
    return {
      receipt: null,
      variableVersion: 0,
      verified: pulled.verified,
      warnings: pulled.warnings,
    };
  }
  const text = decodeValueText(Redacted.value(variable.value));
  const decoded = text === null ? "not valid UTF-8" : decodeReceipt(text, input.target);
  if (typeof decoded === "string") {
    return yield* Effect.fail(
      cliError(
        `The receipt variable ${displayText(name)} in environment ${displayText(input.environmentId)} is not a valid sync receipt (${decoded}). Remove it with \`maruhi var rm ${displayText(name)} --env ${displayText(input.environmentId)}\` and apply again (the next apply rewrites every variable of the target)`,
      ),
    );
  }
  if (decoded.preset !== input.preset) {
    const delivered = Object.keys(decoded.variables).toSorted();
    const orphanHint =
      delivered.length === 0
        ? ""
        : ` Those deliveries stay at the ${decoded.preset} destination and this receipt is their only record, so remove them there yourself first: ${delivered.map(displayText).join(", ")}.`;
    return yield* Effect.fail(
      cliError(
        `The receipt variable ${displayText(name)} in environment ${displayText(input.environmentId)} was written by the ${decoded.preset} preset, but target ${displayText(input.target)} is now configured with preset ${input.preset}, so its deliveries do not describe this destination.${orphanHint} Remove it with \`maruhi var rm ${displayText(name)} --env ${displayText(input.environmentId)}\` and apply again (the next apply rewrites every variable of the target)`,
      ),
    );
  }
  return {
    receipt: decoded,
    variableVersion: variable.version,
    verified: pulled.verified,
    warnings: pulled.warnings,
  };
});

export function receiptVersionWarning(input: {
  readonly target: string;
  readonly environmentId: EnvironmentId;
  readonly variableVersion: number;
}): string | null {
  if (input.variableVersion < RECEIPT_VERSION_WARN_AT) {
    return null;
  }
  const name = receiptVariableName(input.target);
  return `the receipt variable ${displayText(name)} is at version ${input.variableVersion} of the ${RECEIPT_VERSION_LIMIT}-version limit per variable. Before it fills up, delete it with \`maruhi var rm ${displayText(name)} --env ${displayText(input.environmentId)}\`; the next apply starts a fresh receipt and rewrites every variable of the target once`;
}

export function storeReceipt(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly writerUserId: UserId;
  readonly signingKey: CryptoKey;
  readonly receipt: SyncReceipt;
}): Effect.Effect<{ readonly version: number; readonly warnings: readonly string[] }, CliError> {
  return Effect.map(
    pushVariable({
      client: input.client,
      environmentId: input.environmentId,
      recipient: input.recipient,
      name: receiptVariableName(input.receipt.target),
      value: Redacted.make(encodeReceipt(input.receipt), { label: "variable-value" }),
      verified: input.verified,
      resync: input.resync,
      writerUserId: input.writerUserId,
      signingKey: input.signingKey,
      floor: input.floor,
    }),
    (pushed) => ({ version: pushed.version, warnings: pushed.warnings }),
  );
}
