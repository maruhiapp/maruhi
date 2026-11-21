import type { RecipientDek } from "@maruhi/api-schema";
import { type EnvironmentId, type VariableId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import type { FloorHandle, VerifiedSchemaFields } from "../floor-check.ts";
import { generateVariableId } from "../meta-statement.ts";
import type { VerifiedPulledValue } from "../values-verify.ts";
import {
  type ManifestIssueBase,
  manifestIssueBaseOf,
  pullVerifiedEnvironment,
  pullVerifiedEnvironmentMetadata,
} from "../values.ts";

interface ActivationPrev {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly name: string;
  readonly schema: VerifiedSchemaFields;
}

export type PushTarget =
  | { readonly kind: "create"; readonly variableId: VariableId }
  | { readonly kind: "activate"; readonly variableId: VariableId; readonly prev: ActivationPrev }
  | {
      readonly kind: "push";
      readonly variableId: VariableId;
      readonly latest: VerifiedPulledValue;
    };

export function nextVersionOf(target: PushTarget): number {
  return target.kind === "push" ? target.latest.version + 1 : 1;
}

export function prevHashOf(target: PushTarget): string {
  return target.kind === "push" ? target.latest.signedBytesHashHex : "";
}

interface ResolvedTarget {
  readonly target: PushTarget;
  readonly verified: VerifiedProject;
  readonly warnings: readonly string[];
  readonly deks: readonly RecipientDek[] | null;
  readonly issueBase: ManifestIssueBase | null;
}

export const resolveTarget = Effect.fn("push-resolve.resolveTarget")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
}): Effect.fn.Return<ResolvedTarget, CliError> {
  const metadata = yield* pullVerifiedEnvironmentMetadata(input);
  const matches = metadata.variables.filter((variable) => variable.name === input.name);
  if (matches.length > 1) {
    return yield* Effect.fail(
      cliError(
        `Multiple live statements with the same name passed verification (server equivocation): ${input.name}. Refusing to resolve the push target`,
      ),
    );
  }
  const issueBase = manifestIssueBaseOf(metadata);
  const existing = matches[0];
  if (existing === undefined) {
    return {
      target: { kind: "create", variableId: generateVariableId() },
      verified: metadata.verified,
      warnings: metadata.warnings,
      deks: null,
      issueBase,
    };
  }
  if (existing.status === "declared") {
    if (existing.schema === null) {
      return yield* Effect.fail(
        cliError(
          `Variable ${existing.variableId} is declared but carries no schema fields (internal inconsistency)`,
        ),
      );
    }
    return {
      target: {
        kind: "activate",
        variableId: existing.variableId,
        prev: {
          metaVersion: existing.metaVersion,
          metaSigHashHex: existing.metaSigHashHex,
          name: existing.name,
          schema: existing.schema,
        },
      },
      verified: metadata.verified,
      warnings: metadata.warnings,
      deks: null,
      issueBase,
    };
  }
  const pulled = yield* pullVerifiedEnvironment({ ...input, verified: metadata.verified });
  const latest = pulled.variables.find((variable) => variable.variableId === existing.variableId);
  if (latest === undefined) {
    return yield* Effect.fail(
      cliError(
        `The resolved variable ${existing.variableId} (${input.name}) is missing from the value-carrying pull (a concurrent deletion by another member, or an inconsistent server response). Re-run the command`,
      ),
    );
  }
  if (latest.name !== input.name) {
    return yield* Effect.fail(
      cliError(
        `The resolved variable ${existing.variableId} was renamed from ${displayText(input.name)} to ${displayText(latest.name)} before the value fetch (a concurrent rename by another member). Re-run the command`,
      ),
    );
  }
  return {
    target: { kind: "push", variableId: existing.variableId, latest },
    verified: pulled.verified,
    warnings: [...metadata.warnings, ...pulled.warnings],
    deks: pulled.deks,
    issueBase: null,
  };
});
