// Shared implementation of author-signing and wire derivation for
// the layout-v3 variable meta statement (CRYPTO_SPEC §4.2 — with
// the schema fields). The same discipline as meta-statement.ts (the
// v1 creation form): writing "the signed context" and "the
// statement on the wire" as two independent literals makes a
// one-field discrepancy a silent verification failure, so the
// context is built exactly once and the wire is derived
// mechanically.
//
// Users:
//   - `maruhi schema set` (schema.ts) — declaration creation
//     (declared, metaVersion 1) and schema reissue (status
//     unchanged, metaVersion + 1)
//   - `maruhi push`'s activation (push.ts) — declared → active
//     (metaVersion + 1; the schema fields inherit the
//     declaration's values byte-exactly)
//   - `maruhi var rm` (var-rm.ts) — deleting a v3 variable
//     (status deleted, metaVersion + 1; the schema fields and
//     layout keep the previous statement's values byte-exactly —
//     §4.2's deletion convention. The server enforces a mismatch
//     as 422 payload-mismatch)
//
// required is an explicit "true" | "false" string in the signed
// payload (§4.2 — fail-closed: no implementation divergence on
// omitted interpretation), a boolean on the wire (§12-2); max_age_days
// is "" or a decimal in the signed payload, a number or null on the
// wire. The conversions stay inside this module.

import { type EnvironmentId, type UserId, type VariableId } from "@maruhi/core";
import { SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "../chain-sync.ts";
import type { CliError } from "../errors.ts";
import type { VerifiedSchemaFields } from "../floor-check.ts";
import { signStatementAndHash } from "../meta-statement.ts";

/** The shared input of a v3 statement (creation / continuation is fixed by the 3 functions below). */
export interface VariableStatementV3Input {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  /** The display name (NFC-normalized by the caller — §4.2 / §12-1). */
  readonly name: string;
  /** The schema fields (§4.2 — required is a boolean. Mapped to the string form at signing). */
  readonly schema: VerifiedSchemaFields;
  readonly authorUserId: UserId;
  readonly signingKey: CryptoKey;
}

/** The v3 statement's wire form (§12-2 — layoutVersion 3 + schema fields). */
interface WireVariableStatementV3Base {
  readonly suite: typeof SUITE_ID;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly name: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly layoutVersion: 3;
  readonly varType: VerifiedSchemaFields["varType"];
  readonly required: boolean;
  readonly description: string;
  /** null = no declaration. */
  readonly maxAgeDays: number | null;
}

/** The declaration-creation wire form (structurally identical to DeclareVariableMetaStatementSchema). */
export type WireDeclareStatement = WireVariableStatementV3Base & {
  readonly status: "declared";
  readonly metaVersion: 1;
  readonly prevMetaSigHashHex: "";
};

/** The continuation (activation / schema reissue) wire form (structurally identical to Rename V3 / Activate). */
export type WireContinuationStatementV3 = WireVariableStatementV3Base & {
  readonly status: "active" | "declared";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

/** The v3 deletion wire form (structurally identical to DeleteVariableMetaStatementV3Schema). */
export type WireDeleteStatementV3 = WireVariableStatementV3Base & {
  readonly status: "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

export interface SignedStatementV3<Wire> {
  readonly statement: Wire;
  /** The self-computed hash that, once accepted, becomes the local floor's meta record (§6.3 — not a server declaration). */
  readonly metaSigHashHex: string;
}

interface LifecycleFields {
  readonly status: "active" | "declared" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
}

/** The single construction point of the signed context (declared head = the last verified chain head). */
function statementContextV3(input: VariableStatementV3Input, lifecycle: LifecycleFields) {
  return {
    suite: SUITE_ID,
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    target: { kind: "variable", variableId: input.variableId },
    name: input.name,
    status: lifecycle.status,
    layoutVersion: 3,
    schema: {
      varType: input.schema.varType,
      // §4.2: required is a mandatory explicit string ("true" | "false")
      required: input.schema.required ? "true" : "false",
      description: input.schema.description,
      // max_age_days as the signed string ("" = none)
      maxAgeDays: input.schema.maxAgeDays === null ? "" : String(input.schema.maxAgeDays),
    },
    metaVersion: lifecycle.metaVersion,
    prevMetaSigHashHex: lifecycle.prevMetaSigHashHex,
    authorUserId: input.authorUserId,
    chainHeadHashHex: input.verified.state.headHashHex,
    chainHeadSeq: input.verified.state.headSeq,
  } as const;
}

type StatementContextV3 = ReturnType<typeof statementContextV3>;

/** signV3's internal wire form (common across the 3 statuses — each function narrows the public type). */
type WireStatementV3Any = WireVariableStatementV3Base & {
  readonly status: "active" | "declared" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

/** Derives the wire statement mechanically from the signed context (same discipline as meta-statement.ts). */
function toWireStatementV3(context: StatementContextV3, signatureHex: string): WireStatementV3Any {
  return {
    suite: context.suite,
    environmentId: context.environmentId,
    variableId: context.target.variableId,
    name: context.name,
    status: context.status,
    metaVersion: context.metaVersion,
    prevMetaSigHashHex: context.prevMetaSigHashHex,
    chainHeadHashHex: context.chainHeadHashHex,
    chainHeadSeq: context.chainHeadSeq,
    signatureHex,
    layoutVersion: context.layoutVersion,
    varType: context.schema.varType,
    // The wire is boolean (§12-2) — mapped mechanically from the signed string form
    required: context.schema.required === "true",
    description: context.schema.description,
    // The wire is a number or null (§12-2)
    maxAgeDays: context.schema.maxAgeDays === "" ? null : Number(context.schema.maxAgeDays),
  };
}

const signV3 = Effect.fn("schema-statement.signV3")(function* (
  input: VariableStatementV3Input,
  lifecycle: LifecycleFields,
): Effect.fn.Return<SignedStatementV3<WireStatementV3Any>, CliError> {
  const context = statementContextV3(input, lifecycle);
  // Signing + self-computed hash are shared with the v1 creation form (meta-statement.ts)
  const signed = yield* signStatementAndHash(context, input.signingKey);
  return {
    statement: toWireStatementV3(context, signed.signatureHex),
    metaSigHashHex: signed.metaSigHashHex,
  };
});

/**
 * Author-signs a declared creation statement (metaVersion 1, status declared,
 * empty prev — CRYPTO_SPEC §4.2: the only value-free variable creation).
 */
export function signDeclareStatement(
  input: VariableStatementV3Input,
): Effect.Effect<SignedStatementV3<WireDeclareStatement>, CliError> {
  return Effect.map(
    signV3(input, { status: "declared", metaVersion: 1, prevMetaSigHashHex: "" }),
    (signed) => ({
      // lifecycle is already fixed by the literal above — only the wire form's narrowing
      statement: signed.statement as WireDeclareStatement,
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}

/**
 * Author-signs a layout-v3 continuation statement (metaVersion = prev + 1):
 * a schema reissue (status preserved — AUTH_SPEC §12-5; a v1 variable's
 * first reissue raises it to v3, the legitimate direction of §4.2's
 * monotonicity) or an activation (declared → active, bundled with value
 * version 1 — the activation composite). The transition's validity
 * (declared → active only; active → declared forbidden) is guaranteed by
 * the caller deciding status from the verified previous statement (the
 * acceptance authority is the server, §12-5).
 */
export function signContinuationStatementV3<Status extends "active" | "declared">(
  input: VariableStatementV3Input & {
    readonly status: Status;
    readonly prev: { readonly metaVersion: number; readonly metaSigHashHex: string };
  },
): Effect.Effect<
  SignedStatementV3<WireContinuationStatementV3 & { readonly status: Status }>,
  CliError
> {
  return Effect.map(
    signV3(input, {
      status: input.status,
      metaVersion: input.prev.metaVersion + 1,
      prevMetaSigHashHex: input.prev.metaSigHashHex,
    }),
    (signed) => ({
      // status is already fixed by the input literal — only the wire form's narrowing
      statement: signed.statement as WireContinuationStatementV3 & { readonly status: Status },
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}

/**
 * Author-signs a layout-v3 deletion statement (status deleted, metaVersion =
 * prev + 1 — CRYPTO_SPEC §4.2): the schema fields and the name must carry the
 * previous statement's values byte-exactly (the caller passes
 * them from the verified previous statement — the server enforces
 * a mismatch as 422 payload-mismatch).
 */
export function signDeleteStatementV3(
  input: VariableStatementV3Input & {
    readonly prev: { readonly metaVersion: number; readonly metaSigHashHex: string };
  },
): Effect.Effect<SignedStatementV3<WireDeleteStatementV3>, CliError> {
  return Effect.map(
    signV3(input, {
      status: "deleted",
      metaVersion: input.prev.metaVersion + 1,
      prevMetaSigHashHex: input.prev.metaSigHashHex,
    }),
    (signed) => ({
      // lifecycle is already fixed by the literal above — only the wire form's narrowing
      statement: signed.statement as WireDeleteStatementV3,
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}
