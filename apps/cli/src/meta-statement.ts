// Shared implementation of author-signing and wire derivation for
// create statements (metaVersion 1, active, prev empty — AUTH_SPEC
// §12-4 / §12-5 = CRYPTO_SPEC §4.2).
//
// Writing "the signed context" and "the statement on the wire" as
// two independent literals makes a one-field discrepancy a silent
// defect where "the signature is verified against bytes different
// from the wire" (not caught by types; it manifests as a
// verification failure on other clients). MetaStatementContext is
// built exactly once, and the wire is derived mechanically by
// toWireStatement. The difference between push.ts (variable) /
// env-create.ts (environment) is only the target.
//
// Note: test/support/crypto.ts intentionally re-implements the wire
// format independently and functions as a cross-check that detects
// drift from the production implementation, so it is not unified
// into here.

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

/**
 * The client-issued variable ID (AUTH_SPEC §12-1 format). It is a
 * random ID independent of the name: so it does not collide with the
 * ban on renaming display names / reusing deleted IDs (tombstone).
 * Every creation path shares this one implementation (push's create
 * — push-resolve.ts; declaration creation — schema.ts).
 */
export function generateVariableId(): VariableId {
  const id = `v${encodeHex(crypto.getRandomValues(new Uint8Array(12)))}`;
  if (!isVariableId(id)) throw new Error("generated variable id is malformed");
  return decodeVariableId(id);
}

/**
 * Shared implementation of signing + self-computing the
 * signed-bytes hash (the v1 create form = this module; the
 * layout-v3 form = schema-statement.ts). The hash is a
 * self-computed value that, once accepted, becomes the local
 * floor's meta record (§6.3 — not a server declaration).
 */
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

/** The create statement's target (§4.2's target — a variable or the environment itself). */
export type CreateStatementTarget =
  | { readonly kind: "variable"; readonly variableId: VariableId }
  | { readonly kind: "environment" };

export interface CreateStatementInput {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly target: CreateStatementTarget;
  /** The display name (NFC-normalized by the caller — §4.2 / §12-1). */
  readonly name: string;
  readonly authorUserId: UserId;
  readonly signingKey: CryptoKey;
}

/**
 * The single construction point of the context to sign. The
 * declared head is "the last verified chain head" (same as value
 * signing). If the verified view advances on a CAS retry, the
 * caller rebuilds it (each attempt is signed).
 */
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

/** The wire shape of the bundled statement for variable creation (with variableId). */
export type WireVariableCreateStatement = WireCreateStatementBase & {
  readonly variableId: VariableId;
};

/** The wire shape of the bundled statement for environment creation. */
export type WireEnvironmentCreateStatement = WireCreateStatementBase;

/**
 * Derives the wire statement mechanically from the signed context.
 * Every field's source is always the context (never re-enumerate an
 * independent literal — this module's reason to exist).
 */
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
  /** The self-computed hash that, once accepted, becomes the local floor's meta record (§6.3 — not a server declaration). */
  readonly metaSigHashHex: string;
}

/**
 * Author-signs a creation statement (metaVersion 1, active, empty prev) and
 * derives the wire statement mechanically from the very context that was
 * signed, so the signed bytes and the wire can never drift apart (§4.2).
 */
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
