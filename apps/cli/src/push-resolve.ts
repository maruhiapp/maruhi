// Push-target resolution for a push (CRYPTO_SPEC §4.2 / §12-7): the
// name → variableId identification through the verified statements of a
// metadata-only pull, and the PushTarget shapes (create / activate /
// normal push) the send side (push.ts) drives.

import type { RecipientDek } from "@maruhi/api-schema";
import { type EnvironmentId, type VariableId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle, VerifiedSchemaFields } from "./floor-check.ts";
import { generateVariableId } from "./meta-statement.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";
import {
  type ManifestIssueBase,
  manifestIssueBaseOf,
  pullVerifiedEnvironment,
  pullVerifiedEnvironmentMetadata,
} from "./values.ts";

/** The predecessor-statement material of an activation (declared → active — §12-5). */
interface ActivationPrev {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  /** The name at declaration time (an activation never doubles as a rename — the server enforces with 422, §12-5). */
  readonly name: string;
  /** The schema column at declaration time (an activation takes it over byte-exact — the partial-update principle; the layout stays v3). */
  readonly schema: VerifiedSchemaFields;
}

/**
 * The 3 shapes of a push target (§12-5): creation (a composite of value
 * version 1 + metaVersion 1), activation (the first value push onto a
 * declared variable — a composite of value version 1 + a v3 statement with
 * status active [metaVersion + 1] + a manifest), and a normal push onto an
 * existing active variable (meta untouched).
 */
export type PushTarget =
  | { readonly kind: "create"; readonly variableId: VariableId }
  | { readonly kind: "activate"; readonly variableId: VariableId; readonly prev: ActivationPrev }
  | {
      readonly kind: "push";
      readonly variableId: VariableId;
      readonly latest: VerifiedPulledValue;
    };

export function nextVersionOf(target: PushTarget): number {
  // create and activate both write the first value (a declared variable has no value or version — §4.2)
  return target.kind === "push" ? target.latest.version + 1 : 1;
}

export function prevHashOf(target: PushTarget): string {
  return target.kind === "push" ? target.latest.signedBytesHashHex : "";
}

interface ResolvedTarget {
  readonly target: PushTarget;
  /** A view that may have advanced during pull verification (the bounded resync of a future head). */
  readonly verified: VerifiedProject;
  readonly warnings: readonly string[];
  /**
   * The bundled DEK of the value-carrying pull made while resolving an
   * existing active variable (null for a create / activate resolution — a
   * declared variable has no value and needs no value-carrying pull). A raw
   * wire shape, on the premise that it is verified and unwrapped under the
   * same view as verified (§12-7 — eliminating the double fetch with
   * listMine: session-11 ruling 3).
   */
  readonly deks: readonly RecipientDek[] | null;
  /** create / activate paths only: the issuing material of the bundled manifest (null on a normal push). */
  readonly issueBase: ManifestIssueBase | null;
}

/**
 * Resolves the push target from a display name. The resolution is a
 * byte-exact comparison against the verified statements of a metadata-only
 * pull (§12-7 — it carries no values or DEKs, so the server records no
 * var.read) (the lookup key is already NFC-normalized by the caller —
 * §12-1; duplicate same-name actives are already refused by the
 * verification side).
 *
 * A value-carrying pull runs only when the target turns out to be an
 * existing variable: the prev chain (§4.1) needs the verified latest
 * value's signed-bytes hash, which cannot be computed without fetching the
 * ciphertext (var.read is correctly recorded for this fetch). A creation
 * reads no value at all (prev is empty, version 1), so no var.read is
 * recorded — the CLI side of "don't record as read what was never read"
 * (session-11 ruling 3).
 */
export const resolveTarget = Effect.fn("push-resolve.resolveTarget")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3 — the verified pulls used for resolution also go through the floor check [plus a floor commit for the value-carrying one]). */
  readonly floor: FloorHandle;
}): Effect.fn.Return<ResolvedTarget, CliError> {
  const metadata = yield* pullVerifiedEnvironmentMetadata(input);
  // A duplicate same-name pair (whether active / declared) is already
  // refused by the verification side, but kept as a defensive line so the
  // push-target identification does not depend on the response ordering
  // (§4.2's resolution refusal)
  const matches = metadata.variables.filter((variable) => variable.name === input.name);
  if (matches.length > 1) {
    return yield* Effect.fail(
      cliError(
        `Multiple live statements with the same name passed verification (server equivocation): ${input.name}. Refusing to resolve the push target`,
      ),
    );
  }
  // The material of the bundled manifest (§12-5) for a meta operation
  // (create / activate) (from the verified metadata pull). A push to an
  // existing active variable issues no manifest (the issuing triggers are
  // limited — §4.3), so its resolution sets issueBase to null
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
    // The first value push onto a declared variable = the activation
    // composite (§12-5). Since no value exists, no value-carrying pull is
    // made (don't pollute var.read — don't let an unread value be recorded
    // as read). The schema column and name take the declaration-time
    // values over byte-exact (a rename goes through the rename path — the
    // server enforces with 422 payload-mismatch)
    if (existing.schema === null) {
      // declared is layout-v3-only (§4.2) — a v1 declared is already refused at the verification stage
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
    // A concurrent deletion between resolution and value fetch, or an
    // inconsistency across responses (an omission is per-variable evidence
    // at the floor check too). Refuse explicitly instead of falling back
    // to a creation with a wrong prev
    return yield* Effect.fail(
      cliError(
        `The resolved variable ${existing.variableId} (${input.name}) is missing from the value-carrying pull (a concurrent deletion by another member, or an inconsistent server response). Re-run the command`,
      ),
    );
  }
  if (latest.name !== input.name) {
    // A concurrent rename between resolution and value fetch. Never aim a
    // push at a variable that moved to a name different from the input.
    // latest.name is the verified statement's name (§12-2), so a
    // byte-exact comparison suffices
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
    // A push to an existing active variable changes no meta state = issues no manifest (§4.3)
    issueBase: null,
  };
});
