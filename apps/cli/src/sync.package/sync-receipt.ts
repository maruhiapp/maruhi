// The sync receipt (integration-options.md §3 supplement 13 W2 /
// supplement 15 X3 (a)).
//
// "Which variable's version reached which sync target" is stored
// as an **ordinary variable** of the config-pointed environment
// (`receipts.environment`): E2EE + §4.1's write signature (with
// tamper detection), no spec revision needed. It carries no
// value-derived digest (that would be a leakage path for
// guessable values — W2). The version number alone is enough.
//
// Granularity: one variable per target (`sync-receipt:<target>`).
// Since each sync piles on a new version, warn when nearing the
// per-variable version cap (AUTH_SPEC §12-8 — 1,000) (an apply
// whose content does not change is never written, so only "times
// the target actually changed" is written). The active-variable
// cap (1,000 / environment) only costs one slot per target.
//
// Read = a valued pull (pull.ts's pullVariables — decrypts the
// receipt environment), write = push.ts's pushVariable (signed
// with the human's master key. CI does not hold this key and
// cannot write).
//
// Why the name does not start with `MARUHI_`: `run` refuses to
// inject `MARUHI_*`, so pointing a receipt environment at `run` by
// mistake would fail — desirable in itself, but the refusal text
// would say "execution-control name" and confuse the reader.
// Since a name containing `:` is not a POSIX identifier, `run`
// stops with just the variable name as "a name that cannot be
// injected as an environment variable" (the same fail-closed, and
// the wording states the fact).

import type { EnvironmentId } from "@maruhi/core";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import type { DekRecipient } from "../deks.ts";
import { decodeValueText, displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
import { parseJsonRecord } from "../json-record.ts";
import { pullVariables } from "../pull.ts";
import { pushVariable } from "../push.ts";
import { PRESET_IDS, type PresetId } from "./sync-types.ts";

/** What the last apply delivered to one target: variable name → version. */
export interface SyncReceipt {
  readonly version: 1;
  readonly target: string;
  readonly preset: PresetId;
  /** When it was last written (the writer's clock. Display only — never used for judgment). */
  readonly syncedAt: string;
  readonly variables: Readonly<Record<string, number>>;
}

/** The per-variable version cap (AUTH_SPEC §12-8 — apps/server/src/policy.ts's value). */
const RECEIPT_VERSION_LIMIT = 1_000;
/** Warn about nearing the cap starting from this version (100 syncs remaining). */
const RECEIPT_VERSION_WARN_AT = 900;

/** The name of the receipt variable for a target. */
export function receiptVariableName(target: string): string {
  return `sync-receipt:${target}`;
}

/** Interprets a receipt JSON (the reason string when malformed. Never includes the value itself). */
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
  // null prototype: since a variable name is an arbitrary
  // string, a name like `__proto__` must not resolve to an
  // inherited property
  const variables: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const [name, version] of Object.entries(variablesRaw)) {
    if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) {
      return "variables must map names to positive integer versions";
    }
    variables[name] = version;
  }
  return { version: 1, target: expectedTarget, preset: preset as PresetId, syncedAt, variables };
}

/** The receipt's file representation (deterministic: names ascending — the same content is the same bytes). */
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

/** The receipt as last stored, plus the coordinates needed to write the next one. */
export interface LoadedReceipt {
  /** null = this target has no receipt yet (first sync). */
  readonly receipt: SyncReceipt | null;
  /** The receipt variable's current version (0 when absent). Used for the nearing-cap warning. */
  readonly variableVersion: number;
  /** The view used for verification (may have advanced via bounded re-sync). */
  readonly verified: VerifiedProject;
  readonly warnings: readonly string[];
}

/**
 * Reads the receipt for `target` from the receipts environment (a verified,
 * decrypted pull of that environment — the same path as `maruhi pull`).
 * A receipt written by another preset is refused: its deliveries describe a
 * different platform, so acting on it (deletes by name, versions treated as
 * delivered) would be wrong — reset the receipt instead.
 */
export function loadReceipt(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly target: string;
  /** The target's current preset (collated against the receipt writer's preset). */
  readonly preset: PresetId;
}): Effect.Effect<LoadedReceipt, CliError> {
  return Effect.gen(function* () {
    const name = receiptVariableName(input.target);
    // Decrypts only the receipt variable (even if the receipt
    // environment holds the user's secrets, no plaintext is
    // materialized in memory — pull.ts's select contract)
    const pulled = yield* pullVariables({ ...input, select: (n) => n === name });
    const variable = pulled.variables.find((entry) => entry.name === name);
    if (variable === undefined) {
      // Returns the view advanced by bounded re-sync (later pull / push take it over)
      return {
        receipt: null,
        variableVersion: 0,
        verified: pulled.verified,
        warnings: pulled.warnings,
      };
    }
    // Why it is unwrapped: interpreting the receipt JSON (a
    // receipt is a name-to-version mapping, not a secret value.
    // The product is only a struct, and the message carries only
    // a reason)
    const text = decodeValueText(Redacted.value(variable.value));
    const decoded = text === null ? "not valid UTF-8" : decodeReceipt(text, input.target);
    if (typeof decoded === "string") {
      return yield* Effect.fail(
        cliError(
          `The receipt variable ${displayText(name)} in environment ${displayText(input.environmentId)} is not a valid sync receipt (${decoded}). Remove it with \`maruhi var rm ${displayText(name)} --env ${displayText(input.environmentId)}\` and apply again (the next apply rewrites every variable of the target)`,
        ),
      );
    }
    // A receipt with a different preset's destination is a
    // different platform: deleting by name and the "delivered"
    // versions both lose their meaning. Guide recreation by name.
    // Since this receipt is the only record of what is on the old
    // destination, show the name list here before letting it be
    // removed (same shape as driverFailureMessage's pendingHint.
    // maruhi does not go delete the old destination: it never
    // writes to or deletes from a place the config no longer
    // points at)
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
}

/** The nearing-cap warning text (null when not applicable). */
export function receiptVersionWarning(input: {
  readonly target: string;
  readonly environmentId: string;
  readonly variableVersion: number;
}): string | null {
  if (input.variableVersion < RECEIPT_VERSION_WARN_AT) {
    return null;
  }
  const name = receiptVariableName(input.target);
  return `the receipt variable ${displayText(name)} is at version ${input.variableVersion} of the ${RECEIPT_VERSION_LIMIT}-version limit per variable. Before it fills up, delete it with \`maruhi var rm ${displayText(name)} --env ${displayText(input.environmentId)}\`; the next apply starts a fresh receipt and rewrites every variable of the target once`;
}

/**
 * Writes a receipt as a new version of the receipt variable (creating it on
 * the first sync). Signed with the caller's master key like any push (§4.1).
 */
export function storeReceipt(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly writerUserId: string;
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
