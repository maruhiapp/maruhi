// Shared implementation of author-signing and wire derivation for
// the layout-v2 variable meta statement (CRYPTO_SPEC §4.2 — with
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
//   - `maruhi var rm` (var-rm.ts) — deleting a v2 variable
//     (status deleted, metaVersion + 1; the schema fields and
//     layout keep the previous statement's values byte-exactly —
//     §4.2's deletion convention. The server enforces a mismatch
//     as 422 payload-mismatch)
//
// required is an explicit "true" | "false" string in the signed
// payload (§4.2 — fail-closed: no implementation divergence on
// omitted interpretation), a boolean on the wire (§12-2). The
// conversion stays inside this module.

import { SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "../chain-sync.ts";
import type { CliError } from "../errors.ts";
import type { VerifiedSchemaFields } from "../floor-check.ts";
import { signStatementAndHash } from "../meta-statement.ts";

/** The shared input of a v2 statement (creation / continuation is fixed by the 2 functions below). */
export interface VariableStatementV2Input {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly variableId: string;
  /** The display name (NFC-normalized by the caller — §4.2 / §12-1). */
  readonly name: string;
  /** The schema fields (§4.2 — required is a boolean. Mapped to the string form at signing). */
  readonly schema: VerifiedSchemaFields;
  /**
   * The layout to sign: 3 carries `maxAgeDays` (PF6 R9); 2 does not. A new
   * declaration or a schema reissue is 3; a continuation of a v2 variable
   * (activation, deletion) keeps 2 — the schema fields byte-exact (§12-5).
   */
  readonly layoutVersion: 2 | 3;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
}

/** The v2 statement's wire form (§12-2 — layoutVersion 2 + schema fields). */
interface WireVariableStatementV2Base {
  readonly suite: typeof SUITE_ID;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly layoutVersion: 2 | 3;
  readonly varType: VerifiedSchemaFields["varType"];
  readonly required: boolean;
  readonly description: string;
  /** Layout v3 only (null = no declaration; absent on a v2 wire). */
  readonly maxAgeDays?: number | null;
}

/** The declaration-creation wire form (structurally identical to DeclareVariableMetaStatementSchema). */
export type WireDeclareStatement = WireVariableStatementV2Base & {
  readonly status: "declared";
  readonly metaVersion: 1;
  readonly prevMetaSigHashHex: "";
};

/** The continuation (activation / schema reissue) wire form (structurally identical to Rename V2 / Activate). */
export type WireContinuationStatementV2 = WireVariableStatementV2Base & {
  readonly status: "active" | "declared";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

/** The v2 deletion wire form (structurally identical to DeleteVariableMetaStatementV2Schema). */
export type WireDeleteStatementV2 = WireVariableStatementV2Base & {
  readonly status: "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

export interface SignedStatementV2<Wire> {
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
function statementContextV2(input: VariableStatementV2Input, lifecycle: LifecycleFields) {
  return {
    suite: SUITE_ID,
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    target: { kind: "variable", variableId: input.variableId },
    name: input.name,
    status: lifecycle.status,
    layoutVersion: input.layoutVersion,
    schema: {
      varType: input.schema.varType,
      // §4.2: v2's required is a mandatory explicit string ("true" | "false")
      required: input.schema.required ? "true" : "false",
      description: input.schema.description,
      // Layout v3: max_age_days as the signed string ("" = none)
      ...(input.layoutVersion === 3
        ? { maxAgeDays: input.schema.maxAgeDays === null ? "" : String(input.schema.maxAgeDays) }
        : {}),
    },
    metaVersion: lifecycle.metaVersion,
    prevMetaSigHashHex: lifecycle.prevMetaSigHashHex,
    authorUserId: input.authorUserId,
    chainHeadHashHex: input.verified.state.headHashHex,
    chainHeadSeq: input.verified.state.headSeq,
  } as const;
}

type StatementContextV2 = ReturnType<typeof statementContextV2>;

/** signV2's internal wire form (common across the 3 statuses — each function narrows the public type). */
type WireStatementV2Any = WireVariableStatementV2Base & {
  readonly status: "active" | "declared" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

/** Derives the wire statement mechanically from the signed context (same discipline as meta-statement.ts). */
function toWireStatementV2(context: StatementContextV2, signatureHex: string): WireStatementV2Any {
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
    // Layout v3's field rides the wire as a number or null (§12-2)
    ...(context.schema.maxAgeDays === undefined
      ? {}
      : {
          maxAgeDays: context.schema.maxAgeDays === "" ? null : Number(context.schema.maxAgeDays),
        }),
  };
}

function signV2(
  input: VariableStatementV2Input,
  lifecycle: LifecycleFields,
): Effect.Effect<SignedStatementV2<WireStatementV2Any>, CliError> {
  return Effect.gen(function* () {
    const context = statementContextV2(input, lifecycle);
    // Signing + self-computed hash are shared with the v1 creation form (meta-statement.ts)
    const signed = yield* signStatementAndHash(context, input.signingKey);
    return {
      statement: toWireStatementV2(context, signed.signatureHex),
      metaSigHashHex: signed.metaSigHashHex,
    };
  });
}

/**
 * Author-signs a declared creation statement (metaVersion 1, status declared,
 * empty prev — CRYPTO_SPEC §4.2: the only value-free variable creation).
 */
export function signDeclareStatement(
  input: VariableStatementV2Input,
): Effect.Effect<SignedStatementV2<WireDeclareStatement>, CliError> {
  return Effect.map(
    signV2(input, { status: "declared", metaVersion: 1, prevMetaSigHashHex: "" }),
    (signed) => ({
      // lifecycle is already fixed by the literal above — only the wire form's narrowing
      statement: signed.statement as WireDeclareStatement,
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}

/**
 * Author-signs a layout-v2 continuation statement (metaVersion = prev + 1):
 * a schema reissue (status preserved — AUTH_SPEC §12-5) or an activation
 * (declared → active, bundled with value version 1 — the activation
 * composite). The transition's validity (declared → active only;
 * active → declared forbidden) is guaranteed by the caller
 * deciding status from the verified previous statement (the
 * acceptance authority is the server, §12-5).
 */
export function signContinuationStatementV2<Status extends "active" | "declared">(
  input: VariableStatementV2Input & {
    readonly status: Status;
    readonly prev: { readonly metaVersion: number; readonly metaSigHashHex: string };
  },
): Effect.Effect<
  SignedStatementV2<WireContinuationStatementV2 & { readonly status: Status }>,
  CliError
> {
  return Effect.map(
    signV2(input, {
      status: input.status,
      metaVersion: input.prev.metaVersion + 1,
      prevMetaSigHashHex: input.prev.metaSigHashHex,
    }),
    (signed) => ({
      // status is already fixed by the input literal — only the wire form's narrowing
      statement: signed.statement as WireContinuationStatementV2 & { readonly status: Status },
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}

/**
 * Author-signs a layout-v2 deletion statement (status deleted, metaVersion =
 * prev + 1 — CRYPTO_SPEC §4.2): the schema fields and the name must carry the
 * previous statement's values byte-exactly (the caller passes
 * them from the verified previous statement — the server enforces
 * a mismatch as 422 payload-mismatch).
 */
export function signDeleteStatementV2(
  input: VariableStatementV2Input & {
    readonly prev: { readonly metaVersion: number; readonly metaSigHashHex: string };
  },
): Effect.Effect<SignedStatementV2<WireDeleteStatementV2>, CliError> {
  return Effect.map(
    signV2(input, {
      status: "deleted",
      metaVersion: input.prev.metaVersion + 1,
      prevMetaSigHashHex: input.prev.metaSigHashHex,
    }),
    (signed) => ({
      // lifecycle is already fixed by the literal above — only the wire form's narrowing
      statement: signed.statement as WireDeleteStatementV2,
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}
