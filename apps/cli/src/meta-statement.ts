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
export function generateVariableId(): string {
  return `v${encodeHex(crypto.getRandomValues(new Uint8Array(12)))}`;
}

/**
 * Shared implementation of signing + self-computing the
 * signed-bytes hash (the v1 create form = this module; the
 * layout-v2 form = schema-statement.ts). The hash is a
 * self-computed value that, once accepted, becomes the local
 * floor's meta record (§6.3 — not a server declaration).
 */
export function signStatementAndHash(
  context: MetaStatementContext,
  signingKey: CryptoKey,
): Effect.Effect<{ readonly signatureHex: string; readonly metaSigHashHex: string }, CliError> {
  return Effect.gen(function* () {
    const signature = yield* Effect.tryPromise({
      try: () => signMetaStatement({ context, signingKey }),
      catch: () => cliError("Failed to sign the meta statement"),
    });
    if (!signature.ok) {
      return yield* Effect.fail(cliError("Failed to sign the meta statement"));
    }
    const metaSigHash = yield* Effect.tryPromise({
      try: () => computeMetaSignedBytesHash(context),
      catch: () => cliError("Failed to compute the meta-statement signed-bytes hash"),
    });
    if (!metaSigHash.ok) {
      return yield* Effect.fail(cliError("Failed to compute the meta-statement signed-bytes hash"));
    }
    return { signatureHex: signature.value, metaSigHashHex: metaSigHash.value };
  });
}

/** The create statement's target (§4.2's target — a variable or the environment itself). */
export type CreateStatementTarget =
  | { readonly kind: "variable"; readonly variableId: string }
  | { readonly kind: "environment" };

export interface CreateStatementInput {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly target: CreateStatementTarget;
  /** The display name (NFC-normalized by the caller — §4.2 / §12-1). */
  readonly name: string;
  readonly authorUserId: string;
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
  readonly environmentId: string;
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
  readonly variableId: string;
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
): WireCreateStatementBase & { readonly variableId?: string } {
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
    readonly target: { readonly kind: "variable"; readonly variableId: string };
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
