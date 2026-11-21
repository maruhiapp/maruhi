import {
  cryptoEffect,
  type EnvironmentId,
  type UserId,
  type VariableId,
  isVariableId,
  decodeVariableId,
} from "@maruhi/core";
import type { MetaStatementContext } from "@maruhi/crypto";
import { computeMetaSignedBytesHash, encodeHex, signMetaStatement, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { cliError, type CliError } from "./errors.ts";

export function generateVariableId(): VariableId {
  const id = `v${encodeHex(crypto.getRandomValues(new Uint8Array(12)))}`;
  if (!isVariableId(id)) throw new Error("generated variable id is malformed");
  return decodeVariableId(id);
}

export const signStatementAndHash = Effect.fn("meta-statement.signStatementAndHash")(function* (
  context: MetaStatementContext,
  signingKey: CryptoKey,
): Effect.fn.Return<{ readonly signatureHex: string; readonly metaSigHashHex: string }, CliError> {
  const signature = yield* cryptoEffect(() => signMetaStatement({ context, signingKey })).pipe(
    Effect.mapError(() => cliError("Failed to sign the meta statement")),
  );
  const metaSigHash = yield* cryptoEffect(() => computeMetaSignedBytesHash(context)).pipe(
    Effect.mapError(() => cliError("Failed to compute the meta-statement signed-bytes hash")),
  );
  return { signatureHex: signature, metaSigHashHex: metaSigHash };
});

export type CreateStatementTarget =
  | { readonly kind: "variable"; readonly variableId: VariableId }
  | { readonly kind: "environment" };

export interface CreateStatementInput {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly target: CreateStatementTarget;
  readonly name: string;
  readonly authorUserId: UserId;
  readonly signingKey: CryptoKey;
}

function createStatementContext(input: CreateStatementInput) {
  return {
    suite: SUITE_ID,
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    target: input.target,
    name: input.name,
    status: "active",
    metaVersion: 1,
    prevMetaSigHashHex: "",
    authorUserId: input.authorUserId,
    chainHeadHashHex: input.verified.state.headHashHex,
    chainHeadSeq: input.verified.state.headSeq,
  } as const;
}

type CreateStatementContext = ReturnType<typeof createStatementContext>;

interface WireCreateStatementBase {
  readonly suite: typeof SUITE_ID;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly status: "active";
  readonly metaVersion: 1;
  readonly prevMetaSigHashHex: "";
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

export type WireVariableCreateStatement = WireCreateStatementBase & {
  readonly variableId: VariableId;
};

export type WireEnvironmentCreateStatement = WireCreateStatementBase;

function toWireStatement(
  context: CreateStatementContext,
  signatureHex: string,
): WireCreateStatementBase & { readonly variableId?: VariableId } {
  const base = {
    suite: context.suite,
    environmentId: context.environmentId,
    name: context.name,
    status: context.status,
    metaVersion: context.metaVersion,
    prevMetaSigHashHex: context.prevMetaSigHashHex,
    chainHeadHashHex: context.chainHeadHashHex,
    chainHeadSeq: context.chainHeadSeq,
    signatureHex,
  };
  return context.target.kind === "variable"
    ? { ...base, variableId: context.target.variableId }
    : base;
}

export interface SignedCreateStatement<Wire> {
  readonly statement: Wire;
  readonly metaSigHashHex: string;
}

export function signCreateStatement(
  input: CreateStatementInput & {
    readonly target: { readonly kind: "variable"; readonly variableId: VariableId };
  },
): Effect.Effect<SignedCreateStatement<WireVariableCreateStatement>, CliError>;
export function signCreateStatement(
  input: CreateStatementInput & { readonly target: { readonly kind: "environment" } },
): Effect.Effect<SignedCreateStatement<WireEnvironmentCreateStatement>, CliError>;
export function signCreateStatement(
  input: CreateStatementInput,
): Effect.Effect<SignedCreateStatement<WireCreateStatementBase>, CliError> {
  return Effect.gen(function* () {
    const context = createStatementContext(input);
    const signed = yield* signStatementAndHash(context, input.signingKey);
    return {
      statement: toWireStatement(context, signed.signatureHex),
      metaSigHashHex: signed.metaSigHashHex,
    };
  });
}
