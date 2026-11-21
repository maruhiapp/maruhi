import { type EnvironmentId, type VariableId, cryptoEffect } from "@maruhi/core";
import type { MetaVarType, SigningKeyPair } from "@maruhi/crypto";
import { decodeHex, decryptVariable } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { type DekRecipient, environmentKeysFor, missingEpochsOf } from "./deks.ts";
import {
  describeMissingOwnEpochs,
  fillOwnDeviceGaps,
  type OwnDeviceGapFill,
} from "./device-gaps.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle, VerifiedVariableStatement } from "./floor-check.ts";
import { requireEnvironmentInScope } from "./scope.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";
import { pullVerifiedEnvironment } from "./values.ts";

export interface DecryptedVariable {
  readonly variableId: VariableId;
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly varType: MetaVarType;
  readonly required: boolean;
  readonly maxAgeDays: number | null;
  readonly value: Redacted.Redacted<Uint8Array>;
}

export interface DeclaredVariable {
  readonly variableId: VariableId;
  readonly name: string;
  readonly required: boolean;
  readonly varType: MetaVarType;
}

export interface PulledVariables {
  readonly verified: VerifiedProject;
  readonly variables: readonly DecryptedVariable[];
  readonly declared: readonly DeclaredVariable[];
  readonly warnings: readonly string[];
  readonly ownDeviceGapFills: readonly OwnDeviceGapFill[];
}

export function toDeclaredVariables(
  statements: readonly VerifiedVariableStatement[],
): readonly DeclaredVariable[] {
  return statements.map((statement) => ({
    variableId: statement.variableId,
    name: statement.name,
    required: statement.schema?.required ?? true,
    varType: statement.schema?.varType ?? "",
  }));
}

export function missingWrapReason(variable: {
  readonly name: string;
  readonly epoch: number;
}): string {
  return `No DEK for epoch ${variable.epoch} of variable ${displayText(variable.name)} was distributed (your wrap is missing)`;
}

export const decryptVerifiedValue = Effect.fnUntraced(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variable: VerifiedPulledValue;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly chainEpoch: number;
}): Effect.fn.Return<Redacted.Redacted<Uint8Array>, CliError> {
  const variable = input.variable;
  if (variable.epoch > input.chainEpoch) {
    return yield* Effect.fail(
      cliError(
        `Variable ${displayText(variable.name)} declares epoch ${variable.epoch}, beyond the chain's current epoch (${input.chainEpoch}) (inconsistent with the verified view)`,
      ),
    );
  }
  const dek = input.deksByEpoch.get(variable.epoch);
  if (dek === undefined) {
    return yield* Effect.fail(cliError(missingWrapReason(variable)));
  }
  const nonce = decodeHex(variable.nonceHex);
  const ciphertext = decodeHex(variable.ciphertextHex);
  if (nonce === null || ciphertext === null) {
    return yield* Effect.fail(
      cliError(`Variable ${displayText(variable.name)} has a malformed ciphertext`),
    );
  }
  const plaintext = yield* cryptoEffect(() =>
    decryptVariable({
      dek: Redacted.value(dek),
      context: {
        projectId: input.verified.projectId,
        environmentId: input.environmentId,
        epoch: variable.epoch,
        variableId: variable.variableId,
        version: variable.version,
      },
      nonce,
      ciphertext,
    }),
  ).pipe(
    Effect.mapError(() =>
      cliError(
        `Cannot decrypt variable ${displayText(variable.name)} (context mismatch or corrupted ciphertext — possibly replaced by the server)`,
      ),
    ),
  );
  return Redacted.make(plaintext, { label: "variable-value" });
});

function selectedVariables(
  variables: readonly VerifiedPulledValue[],
  select: ((name: string) => boolean) | undefined,
): readonly VerifiedPulledValue[] {
  return select === undefined ? variables : variables.filter((variable) => select(variable.name));
}

export const pullVariables = Effect.fn("pull.pullVariables")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly select?: (name: string) => boolean;
  readonly fillOwnDeviceGaps?: { readonly signingKeyPair: SigningKeyPair };
}): Effect.fn.Return<PulledVariables, CliError> {
  yield* requireEnvironmentInScope({
    verified: input.verified,
    userId: input.recipient.userId,
    environmentId: input.environmentId,
    operation: "pull values from",
  });
  const pulled = yield* pullVerifiedEnvironment(input);
  const verified = pulled.verified;

  const keys = yield* environmentKeysFor({
    client: input.client,
    verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    prefetched: pulled.deks,
  });
  const deksByEpoch = keys.deksByEpoch;

  const missingEpochs = missingEpochsOf(keys);
  const warnings =
    missingEpochs.length === 0
      ? pulled.warnings
      : [
          ...pulled.warnings,
          describeMissingOwnEpochs(verified.projectId, input.environmentId, missingEpochs),
        ];

  const selected = selectedVariables(pulled.variables, input.select);
  const decrypted = yield* Effect.forEach(
    selected,
    (variable) =>
      decryptVerifiedValue({
        verified,
        environmentId: input.environmentId,
        variable,
        deksByEpoch,
        chainEpoch: keys.currentEpoch,
      }).pipe(
        Effect.match({
          onSuccess: (plaintext) => ({ ok: true as const, plaintext }),
          onFailure: (error) => ({ ok: false as const, error }),
        }),
      ),
    { concurrency: "unbounded" },
  );
  const results: DecryptedVariable[] = [];
  for (const [index, outcome] of decrypted.entries()) {
    if (!outcome.ok) {
      return yield* Effect.fail(outcome.error);
    }
    const variable = selected[index]!;
    const plaintext = outcome.plaintext;
    results.push({
      variableId: variable.variableId,
      name: variable.name,
      version: variable.version,
      epoch: variable.epoch,
      varType: variable.schema?.varType ?? "",
      required: variable.schema?.required ?? false,
      maxAgeDays: variable.schema?.maxAgeDays ?? null,
      value: plaintext,
    });
  }
  const ownDeviceGapFills = yield* fillOwnDeviceGaps({
    client: input.client,
    verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    signer: input.fillOwnDeviceGaps,
    currentEpoch: keys.currentEpoch,
    deksByEpoch,
    rows: pulled.deks,
  });
  return {
    verified,
    variables: results,
    declared: toDeclaredVariables(pulled.declared),
    warnings,
    ownDeviceGapFills,
  };
});
