import { type EnvironmentId, type UserId, type VariableId } from "@maruhi/core";
import { SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "../chain-sync.ts";
import type { CliError } from "../errors.ts";
import type { VerifiedSchemaFields } from "../floor-check.ts";
import { signStatementAndHash } from "../meta-statement.ts";

export interface VariableStatementV3Input {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly name: string;
  readonly schema: VerifiedSchemaFields;
  readonly authorUserId: UserId;
  readonly signingKey: CryptoKey;
}

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
  readonly maxAgeDays: number | null;
}

export type WireDeclareStatement = WireVariableStatementV3Base & {
  readonly status: "declared";
  readonly metaVersion: 1;
  readonly prevMetaSigHashHex: "";
};

export type WireContinuationStatementV3 = WireVariableStatementV3Base & {
  readonly status: "active" | "declared";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

export type WireDeleteStatementV3 = WireVariableStatementV3Base & {
  readonly status: "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

export interface SignedStatementV3<Wire> {
  readonly statement: Wire;
  readonly metaSigHashHex: string;
}

interface LifecycleFields {
  readonly status: "active" | "declared" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
}

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
      required: input.schema.required ? "true" : "false",
      description: input.schema.description,
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

type WireStatementV3Any = WireVariableStatementV3Base & {
  readonly status: "active" | "declared" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

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
    required: context.schema.required === "true",
    description: context.schema.description,
    maxAgeDays: context.schema.maxAgeDays === "" ? null : Number(context.schema.maxAgeDays),
  };
}

const signV3 = Effect.fn("schema-statement.signV3")(function* (
  input: VariableStatementV3Input,
  lifecycle: LifecycleFields,
): Effect.fn.Return<SignedStatementV3<WireStatementV3Any>, CliError> {
  const context = statementContextV3(input, lifecycle);
  const signed = yield* signStatementAndHash(context, input.signingKey);
  return {
    statement: toWireStatementV3(context, signed.signatureHex),
    metaSigHashHex: signed.metaSigHashHex,
  };
});

export function signDeclareStatement(
  input: VariableStatementV3Input,
): Effect.Effect<SignedStatementV3<WireDeclareStatement>, CliError> {
  return Effect.map(
    signV3(input, { status: "declared", metaVersion: 1, prevMetaSigHashHex: "" }),
    (signed) => ({
      statement: signed.statement as WireDeclareStatement,
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}

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
      statement: signed.statement as WireContinuationStatementV3 & { readonly status: Status },
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}

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
      statement: signed.statement as WireDeleteStatementV3,
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}
