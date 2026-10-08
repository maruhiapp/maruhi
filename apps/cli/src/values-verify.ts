// Per-statement verification of distributed values and metadata (CRYPTO_SPEC
// §6.3): the wire layout interpretation, the failure classification
// (future / rejected / evidence), the crypto-call wrappers, and the
// per-statement-set verification loops the pull pipeline in values.ts drives.

import type {
  CheckpointValueSnapshot,
  DistributedEncryptedPayload,
  DistributedEnvironmentManifest,
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
} from "@maruhi/api-schema";
import {
  cryptoEffect,
  CryptoMetaStatementInvalidError,
  CryptoUnsupportedMetaLayoutError,
  CryptoValueInvalidError,
  type WrappedCryptoError,
  type EnvironmentId,
  type UserId,
  type VariableId,
} from "@maruhi/core";
import type { MetaStatementContext, MetaVariableSchema } from "@maruhi/crypto";
import {
  SUPPORTED_META_LAYOUT_VERSIONS,
  verifyDistributedMetaStatement,
  verifyDistributedValue,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { cryptoErrorKind } from "./crypto-error-kind.ts";
import { displayText } from "./display.ts";
import type {
  VerifiedEnvironmentStatement,
  VerifiedMetaEvidence,
  VerifiedSchemaFields,
  VerifiedTombstone,
  VerifiedVariableStatement,
} from "./floor-check.ts";

/** One pulled variable whose write signature and statement passed §6.3. */
export interface VerifiedPulledValue {
  readonly variableId: VariableId;
  /** The verified statement's name (no other name is trusted — §12-2). */
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  /** The signed prev (the signed-bytes hash of the immediately preceding version. Empty for version 1). */
  readonly prevValueSigHashHex: string;
  /**
   * Locally recomputed hash of the value's signed bytes — the prev anchor
   * for pushing the next version (the §4.1 chain) and the comparator for
   * same-coordinate equivocation evidence (§14.2-5).
   */
  readonly signedBytesHashHex: string;
  /** The verified statement's metaVersion (the basis of the rollback / fork checks). */
  readonly metaVersion: number;
  /** The statement's signed-bytes hash (self-computed — the same-metaVersion difference check). */
  readonly metaSignedBytesHashHex: string;
  /** The signed prev (the signed-bytes hash of the immediately preceding metaVersion. Empty for metaVersion 1). */
  readonly prevMetaSigHashHex: string;
  /** The value signature's declared head (included in the fork evidence of a floor check — §6.3 / §14.2-5). */
  readonly valueChainHeadSeq: number;
  readonly valueChainHeadHashHex: string;
  /** The meta-statement's declared head (same). */
  readonly metaChainHeadSeq: number;
  readonly metaChainHeadHashHex: string;
  /** The verified value signature and its attribution (self-contained fork evidence — §14.2-5). */
  readonly valueSignatureHex: string;
  readonly writerUserId: UserId;
  readonly writerKeyFingerprintHex: string;
  /** The verified statement signature and its attribution (same). */
  readonly metaSignatureHex: string;
  readonly authorUserId: UserId;
  readonly authorKeyFingerprintHex: string;
  /** The statement's wire layoutVersion (omitted = 1 — §12-2). */
  readonly layoutVersion: number;
  /** The schema column of layout v3 (null for v1. The type is a declaration — advisory §14.3-7). */
  readonly schema: VerifiedSchemaFields | null;
}

/** One pulled variable on the wire (statement + value — AUTH_SPEC §12-7 / §14-2). */
export interface PulledWire {
  readonly variableId: VariableId;
  readonly statement: DistributedVariableMetaStatement;
  readonly value: DistributedEncryptedPayload;
}

export type VerifyOutcome<T> =
  | { readonly kind: "ok"; readonly value: T }
  | { readonly kind: "future" }
  | {
      readonly kind: "rejected";
      readonly message: string;
      /**
       * Whether it is evidence (a contradiction between signed distributed
       * data and the chain notarization / coordinates — a re-run does not
       * resolve it). false is only the "honest breaking mode" =
       * UnsupportedMetaLayout (the client needs an update — CRYPTO_SPEC
       * §4.2 / ruling CR); never collapsed into the tampering-suspect
       * classification (same shape as checkpoint-integrity.ts's rejected).
       */
      readonly evidence: boolean;
    };

/** Whether the claimed AAD's coordinate components match the expected coordinates (verified genesis / requested env / response's outer id) (§6.3-5). */
function coordinatesMatch(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  variable: PulledWire,
): boolean {
  const aad = variable.value.aad;
  return (
    aad.projectId === verified.projectId &&
    aad.environmentId === environmentId &&
    aad.variableId === variable.variableId
  );
}

/**
 * Verification failure reasons → future / rejected. chain-head-future and
 * "a head beyond the own view declared by a new member of an unsynced
 * interval (the writer / author is unknown AND the declared seq > own
 * head)" go to the bounded-resync entry (future). Everything else is a
 * refusal (the classification is shared between value and meta).
 *
 * UnsupportedMetaLayout (a layoutVersion outside the supported range
 * {1, 3} — checked by crypto **before** the signature verification) is an
 * honest breaking mode meaning "the client needs an update", and is not
 * collapsed into the tampering-suspect wording (CRYPTO_SPEC §4.2 — ruling
 * CR).
 */
/** Whether a failure can be classified as future (the bounded-resync entry) (§6.3-2b). */
function isFutureFailure(
  verified: VerifiedProject,
  chainHeadSeq: number,
  error: WrappedCryptoError,
): boolean {
  if (
    !(error instanceof CryptoValueInvalidError) &&
    !(error instanceof CryptoMetaStatementInvalidError)
  ) {
    return false;
  }
  const unknownSigner = error.reason === "writer-unknown" || error.reason === "author-unknown";
  return (
    error.reason === "chain-head-future" ||
    (unknownSigner && chainHeadSeq > verified.history.headSeq)
  );
}

function failureOutcome<T>(
  verified: VerifiedProject,
  label: string,
  chainHeadSeq: number,
  error: WrappedCryptoError,
): VerifyOutcome<T> {
  if (error instanceof CryptoUnsupportedMetaLayoutError) {
    return {
      kind: "rejected",
      // An honest breaking mode (the client needs an update) — not evidence of tampering (ruling CR)
      evidence: false,
      message: `${label} uses statement layout version ${error.layoutVersion}, which this CLI does not support (supported: ${SUPPORTED_META_LAYOUT_VERSIONS.join(", ")}). This is not a tampering indication — update the maruhi CLI (CRYPTO_SPEC §4.2)`,
    };
  }
  if (isFutureFailure(verified, chainHeadSeq, error)) {
    return { kind: "future" };
  }
  return {
    kind: "rejected",
    evidence: true,
    message: `Verification of ${label} failed (reason=${"reason" in error ? error.reason : cryptoErrorKind(error)}). It may have been replaced or forged by the server`,
  };
}

/**
 * Verified statement → the shared evidence-material fields (§14.2-5's
 * self-containedness). The mapping of the 7 fields the floor check and the
 * evidence display use is unified here (a hand-written re-enumeration that
 * drops one field would silently weaken the equivocation evidence without
 * failing a test).
 */
function metaEvidenceFields(
  statement: DistributedVariableMetaStatement | DistributedEnvironmentMetaStatement,
  metaSigHashHex: string,
): Omit<VerifiedMetaEvidence, "status"> {
  return {
    metaVersion: statement.metaVersion,
    metaSigHashHex,
    chainHeadSeq: statement.chainHeadSeq,
    chainHeadHashHex: statement.chainHeadHashHex,
    signatureHex: statement.signatureHex,
    authorUserId: statement.authorUserId,
    authorKeyFingerprintHex: statement.authorKeyFingerprintHex,
  };
}

/**
 * Interpreting a variable statement's wire schema-layout fields (§12-2): a
 * v1 has all of them absent, a v3 has all of them present (maxAgeDays null
 * = no declaration). A partial presence is a shape an honest server's
 * response never has (the server guarantees the join of stored rows —
 * §12-2), so it is refused. layoutVersion's wire type is an integer with no
 * fixed upper bound (explicit values ≥ 2), and the supported-range ({1, 3})
 * check happens in the crypto layer (metaContextRejection) before the
 * signature verification — the range is not checked here (the retired 2
 * or a future layout must surface as "unsupported layout", not as a shape
 * error).
 */
type WireStatementLayout =
  | { readonly layoutVersion: 1; readonly schema: null }
  | { readonly layoutVersion: number; readonly schema: VerifiedSchemaFields };

function wireStatementLayoutOf(
  statement: DistributedVariableMetaStatement,
): WireStatementLayout | null {
  const present = [
    statement.layoutVersion !== undefined,
    statement.varType !== undefined,
    statement.required !== undefined,
    statement.description !== undefined,
  ].filter(Boolean).length;
  if (present === 0) {
    return { layoutVersion: 1, schema: null };
  }
  if (
    statement.layoutVersion === undefined ||
    statement.varType === undefined ||
    statement.required === undefined ||
    statement.description === undefined
  ) {
    return null;
  }
  if (!maxAgeCoupled(statement.layoutVersion, statement.maxAgeDays !== undefined)) {
    return null;
  }
  return {
    layoutVersion: statement.layoutVersion,
    schema: {
      varType: statement.varType,
      required: statement.required,
      description: statement.description,
      maxAgeDays: statement.maxAgeDays ?? null,
    },
  };
}

/**
 * Layout v3 carries maxAgeDays (null = none — §12-2; its absence is the same
 * partial-set refusal). Any other layout is refused later as unsupported
 * (the crypto layer's typed error), so the coupling is only judged for 3.
 */
function maxAgeCoupled(layoutVersion: number, present: boolean): boolean {
  return layoutVersion !== 3 || present;
}

/** The refusal message for a distribution carrying a partial schema-layout field set (§12-2's all-or-nothing rule). */
function partialLayoutMessage(label: string): string {
  return `${label} carries only part of the layout-v3 field set (layoutVersion / varType / required / description / maxAgeDays must be all present or all absent — an inconsistent server response)`;
}

/** The schema-layout fields passed to crypto's signed context (required and max_age_days in the signature convention's string forms — §4.2). */
function contextLayoutFields(
  layout: WireStatementLayout | null,
): Pick<MetaStatementContext, "layoutVersion" | "schema"> {
  if (layout === null || layout.schema === null) {
    return {};
  }
  const schema: MetaVariableSchema = {
    varType: layout.schema.varType,
    required: layout.schema.required ? "true" : "false",
    description: layout.schema.description,
    // "" = no declaration
    maxAgeDays: layout.schema.maxAgeDays === null ? "" : String(layout.schema.maxAgeDays),
  };
  return { layoutVersion: layout.layoutVersion, schema };
}

/**
 * The composite verification of a statement (§6.3). The context is
 * assembled locally from the expected coordinates. A variable statement's
 * schema-layout fields are interpreted from the wire by the caller and passed
 * in (an environment meta stays v1 — §4.2 — and carries no layout).
 */
async function verifyStatement(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  target: MetaStatementContext["target"],
  statement: DistributedVariableMetaStatement | DistributedEnvironmentMetaStatement,
  label: string,
  layout?: WireStatementLayout | null,
): Promise<VerifyOutcome<{ readonly signedBytesHashHex: string }>> {
  return await Effect.runPromise(
    cryptoEffect(() =>
      verifyDistributedMetaStatement({
        history: verified.history,
        context: {
          suite: statement.suite,
          projectId: verified.projectId,
          environmentId,
          target,
          name: statement.name,
          status: statement.status,
          ...contextLayoutFields(layout ?? null),
          metaVersion: statement.metaVersion,
          prevMetaSigHashHex: statement.prevMetaSigHashHex,
          authorUserId: statement.authorUserId,
          chainHeadHashHex: statement.chainHeadHashHex,
          chainHeadSeq: statement.chainHeadSeq,
        },
        authorKeyFingerprintHex: statement.authorKeyFingerprintHex,
        signatureHex: statement.signatureHex,
      }),
    ).pipe(
      Effect.match({
        onSuccess: (value): VerifyOutcome<{ readonly signedBytesHashHex: string }> => ({
          kind: "ok",
          value,
        }),
        onFailure: (error): VerifyOutcome<{ readonly signedBytesHashHex: string }> =>
          failureOutcome(verified, label, statement.chainHeadSeq, error),
      }),
    ),
  );
}

/**
 * Verifying a variable statement (the entry of verifyStatement with the
 * wire schema-layout interpretation). A partial field set is refused here; on
 * success the layout (for display, carry-over, digest material) is also
 * returned.
 */
async function verifyVariableStatement(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  statement: DistributedVariableMetaStatement,
  label: string,
): Promise<
  VerifyOutcome<{ readonly signedBytesHashHex: string; readonly layout: WireStatementLayout }>
> {
  const layout = wireStatementLayoutOf(statement);
  if (layout === null) {
    return { kind: "rejected", message: partialLayoutMessage(label), evidence: true };
  }
  const outcome = await verifyStatement(
    verified,
    environmentId,
    { kind: "variable", variableId: statement.variableId },
    statement,
    label,
    layout,
  );
  if (outcome.kind !== "ok") {
    return outcome;
  }
  return { kind: "ok", value: { signedBytesHashHex: outcome.value.signedBytesHashHex, layout } };
}

async function verifyOne(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  variable: PulledWire,
): Promise<VerifyOutcome<VerifiedPulledValue>> {
  const payload = variable.value;
  const statement = variable.statement;
  // Coordinate agreement (§6.3-5): verification and decryption run on the
  // expected coordinates, so a mismatch fails either way — the explicit
  // check visualizes *which* coordinate disagreed. Since the name cannot be
  // trusted until the statement verification passes, messages identify by
  // variableId
  if (!coordinatesMatch(verified, environmentId, variable)) {
    return {
      kind: "rejected",
      evidence: true,
      message: `Variable ${displayText(variable.variableId)} declares AAD coordinates that do not match the requested context (an inconsistent server response)`,
    };
  }
  if (statement.environmentId !== environmentId || statement.variableId !== variable.variableId) {
    return {
      kind: "rejected",
      evidence: true,
      message: `Variable ${displayText(variable.variableId)} has statement coordinates that do not match the requested context (possible renaming or transplantation)`,
    };
  }
  // The name → variableId mapping must go through a verified statement (§4.2 / §12-7)
  const verifiedStatement = await verifyVariableStatement(
    verified,
    environmentId,
    statement,
    `variable ${displayText(variable.variableId)}'s meta statement`,
  );
  if (verifiedStatement.kind !== "ok") {
    return verifiedStatement;
  }
  if (statement.status !== "active") {
    // deleted = the transport shape of an unauthorized undeletion;
    // declared = juxtaposing a value onto a valueless declaration (declared
    // is the only legitimate valueless state — §6.3; bundling a value is
    // the opposite contradiction)
    return {
      kind: "rejected",
      evidence: true,
      message: `Variable ${displayText(variable.variableId)} was served a ${statement.status} statement together with a value (a value must only accompany an active statement — an inconsistent server response)`,
    };
  }
  return await Effect.runPromise(
    cryptoEffect(() =>
      verifyDistributedValue({
        history: verified.history,
        context: {
          suite: payload.suite,
          projectId: verified.projectId,
          environmentId,
          epoch: payload.aad.epoch,
          variableId: variable.variableId,
          version: payload.aad.version,
          nonceHex: payload.nonceHex,
          ciphertextHex: payload.ciphertextHex,
          prevValueSigHashHex: payload.prevValueSigHashHex,
          writerUserId: payload.writerUserId,
          chainHeadHashHex: payload.chainHeadHashHex,
          chainHeadSeq: payload.chainHeadSeq,
        },
        writerKeyFingerprintHex: payload.writerKeyFingerprintHex,
        signatureHex: payload.signatureHex,
      }),
    ).pipe(
      Effect.match({
        onSuccess: (result): VerifyOutcome<VerifiedPulledValue> => ({
          kind: "ok",
          value: {
            variableId: variable.variableId,
            name: statement.name,
            version: payload.aad.version,
            epoch: payload.aad.epoch,
            nonceHex: payload.nonceHex,
            ciphertextHex: payload.ciphertextHex,
            prevValueSigHashHex: payload.prevValueSigHashHex,
            signedBytesHashHex: result.signedBytesHashHex,
            metaVersion: statement.metaVersion,
            metaSignedBytesHashHex: verifiedStatement.value.signedBytesHashHex,
            prevMetaSigHashHex: statement.prevMetaSigHashHex,
            valueChainHeadSeq: payload.chainHeadSeq,
            valueChainHeadHashHex: payload.chainHeadHashHex,
            metaChainHeadSeq: statement.chainHeadSeq,
            metaChainHeadHashHex: statement.chainHeadHashHex,
            valueSignatureHex: payload.signatureHex,
            writerUserId: payload.writerUserId,
            writerKeyFingerprintHex: payload.writerKeyFingerprintHex,
            metaSignatureHex: statement.signatureHex,
            authorUserId: statement.authorUserId,
            authorKeyFingerprintHex: statement.authorKeyFingerprintHex,
            layoutVersion: verifiedStatement.value.layout.layoutVersion,
            schema: verifiedStatement.value.layout.schema,
          },
        }),
        onFailure: (error): VerifyOutcome<VerifiedPulledValue> =>
          failureOutcome(
            verified,
            `variable ${displayText(statement.name)}'s value signature`,
            payload.chainHeadSeq,
            error,
          ),
      }),
    ),
  );
}

export interface PullWire {
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly PulledWire[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  /**
   * The latest statements of declared variables (§12-7 — no value or
   * version exists). Absent = no declared.
   */
  readonly declaredVariables?: readonly DistributedVariableMetaStatement[] | undefined;
  /**
   * The latest manifest (§12-7 — required on the wire; the schema
   * refuses an omission at decode — the same verdict as a dropped
   * environment statement, §6.3).
   */
  readonly manifest: DistributedEnvironmentManifest;
  /**
   * The enumeration of value snapshots at the checkpoint (§12-7 — rule
   * 2's material. An omission on an environment with a baseline is refused
   * by checkpoint-integrity.ts).
   */
  readonly checkpointSnapshot?: CheckpointValueSnapshot | undefined;
}

/** Verifying the environment's own statement (including that it is active). Returns the evidence material. */
export async function verifyEnvironmentStatement(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  statement: DistributedEnvironmentMetaStatement,
): Promise<VerifyOutcome<VerifiedEnvironmentStatement>> {
  // The verified chain is the authority for deletion (CRYPTO_SPEC §6.3
  // "Chain-deleted environments"): a server distributing a chain-deleted
  // environment as live is resurrecting it
  const deletedAtSeq = verified.state.environments.get(environmentId)?.deletedAtSeq ?? null;
  if (deletedAtSeq !== null) {
    return {
      kind: "rejected",
      evidence: true,
      message: `Environment ${displayText(environmentId)} is deleted on the verified chain (delete_environment at seq ${deletedAtSeq}), yet the server distributed it as live (an unauthorized resurrection — a deleted environment is never distributed)`,
    };
  }
  if (statement.environmentId !== environmentId) {
    return {
      kind: "rejected",
      evidence: true,
      message: `The environment statement's coordinates do not match the requested environment ${environmentId} (possible transplantation)`,
    };
  }
  const result = await verifyStatement(
    verified,
    environmentId,
    { kind: "environment" },
    statement,
    `environment ${environmentId}'s meta statement`,
  );
  if (result.kind !== "ok") {
    return result;
  }
  return {
    kind: "ok",
    value: {
      status: "active",
      name: statement.name,
      ...metaEvidenceFields(statement, result.value.signedBytesHashHex),
    },
  };
}

/** Verifying a deleted variable's tombstone statement (a juxtaposition with the active / declared side = the transport shape of an unauthorized undeletion, also refused). */
export async function verifyDeletedStatements(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  deleted: readonly DistributedVariableMetaStatement[],
  liveIds: ReadonlySet<string>,
): Promise<VerifyOutcome<readonly VerifiedTombstone[]>> {
  // Each statement's signature verification is independent, so they run in
  // parallel; the checks below then replay in input order and the reported
  // first failure is unchanged (P-5).
  const outcomes = await Promise.all(
    deleted.map((statement) =>
      verifyVariableStatement(
        verified,
        environmentId,
        statement,
        `deleted variable ${displayText(statement.variableId)}'s meta statement`,
      ),
    ),
  );
  const seen = new Set<string>();
  const tombstones: VerifiedTombstone[] = [];
  for (const [index, statement] of deleted.entries()) {
    if (statement.environmentId !== environmentId) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Deleted variable ${displayText(statement.variableId)} has statement coordinates that do not match the requested environment`,
      };
    }
    if (seen.has(statement.variableId) || liveIds.has(statement.variableId)) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Variable ${displayText(statement.variableId)} was served as both live (active or declared) and deleted (an unauthorized undeletion = equivocation in transit)`,
      };
    }
    seen.add(statement.variableId);
    if (statement.status !== "deleted") {
      return {
        kind: "rejected",
        evidence: true,
        message: `A non-deleted statement was served in the deleted list: ${displayText(statement.variableId)}`,
      };
    }
    const result = outcomes[index]!;
    if (result.kind !== "ok") {
      return result;
    }
    tombstones.push({
      variableId: statement.variableId,
      // deleted keeps the immediately preceding active name (§4.2) — the
      // only verified source of a deleted variable's display name (name
      // resolution for the needs-rotation flag — AUDIT_SPEC §7)
      name: statement.name,
      status: "deleted",
      ...metaEvidenceFields(statement, result.value.signedBytesHashHex),
    });
  }
  return { kind: "ok", value: tombstones };
}

/** The name check of the verified live (active + declared) set: a duplicate same name = resolution refusal (§4.2), non-NFC = a warning (SHOULD). */
export function checkVerifiedNames(
  values: readonly { readonly variableId: VariableId; readonly name: string }[],
  warnings: string[],
): string | null {
  const seenNames = new Set<string>();
  for (const value of values) {
    // Uniqueness is a byte-exact comparison (§12-1. Equivalent to NFC equality when every accepted name is NFC)
    if (seenNames.has(value.name)) {
      return `Multiple live statements with the same name passed verification (server equivocation): ${displayText(value.name)}. Refusing name resolution`;
    }
    seenNames.add(value.name);
    if (value.name.normalize("NFC") !== value.name) {
      warnings.push(
        `Variable ${displayText(value.variableId)} has a name that is not NFC-normalized (an honest server would not accept it — beware that visually identical names may coexist)`,
      );
    }
  }
  return null;
}

/**
 * Verifying the variable statements of a metadata-only pull (§12-7's
 * metadata-only mode). The coordinate-agreement and variableId-duplicate
 * refusal checks follow the same discipline as the value-carrying pull's
 * verifyOne; only the value-signature verification is absent. declared
 * flows mixed into the same list as active (§12-7 — the status field
 * discriminates), so only a deleted's infiltration is refused.
 */
export async function verifyVariableStatements(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  statements: readonly DistributedVariableMetaStatement[],
): Promise<
  VerifyOutcome<{
    readonly values: readonly VerifiedVariableStatement[];
    readonly ids: Set<string>;
  }>
> {
  // Parallel signature verifications; the checks replay in input order so
  // the first reported failure is unchanged (P-5).
  const outcomes = await Promise.all(
    statements.map((statement) =>
      verifyVariableStatement(
        verified,
        environmentId,
        statement,
        `variable ${displayText(statement.variableId)}'s meta statement`,
      ),
    ),
  );
  const seenIds = new Set<string>();
  const values: VerifiedVariableStatement[] = [];
  for (const [index, statement] of statements.entries()) {
    if (statement.environmentId !== environmentId) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Variable ${displayText(statement.variableId)} has statement coordinates that do not match the requested context (possible renaming or transplantation)`,
      };
    }
    if (seenIds.has(statement.variableId)) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Duplicate variable IDs within one response (an inconsistent server response): ${statement.variableId}`,
      };
    }
    seenIds.add(statement.variableId);
    const outcome = outcomes[index]!;
    if (outcome.kind !== "ok") {
      return outcome;
    }
    if (statement.status === "deleted") {
      return {
        kind: "rejected",
        evidence: true,
        message: `Variable ${displayText(statement.variableId)} was served a deleted statement in the live list (a possible unauthorized undeletion)`,
      };
    }
    values.push({
      variableId: statement.variableId,
      name: statement.name,
      status: statement.status,
      ...metaEvidenceFields(statement, outcome.value.signedBytesHashHex),
      layoutVersion: outcome.value.layout.layoutVersion,
      schema: outcome.value.layout.schema,
    });
  }
  return { kind: "ok", value: { values, ids: seenIds } };
}

/**
 * Verifying the declaredVariables (§12-7) of a value-bearing response. The
 * implementation point of CRYPTO_SPEC §6.3's value-distribution
 * requirement: a verified statement with status active appearing in this
 * list is refused as "a value omission" (declared is the only legitimate
 * valueless state).
 */
export async function verifyDeclaredStatements(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  declared: readonly DistributedVariableMetaStatement[],
  activeIds: ReadonlySet<string>,
): Promise<
  VerifyOutcome<{
    readonly values: readonly VerifiedVariableStatement[];
    readonly ids: Set<string>;
  }>
> {
  // Parallel signature verifications; the checks replay in input order so
  // the first reported failure is unchanged (P-5).
  const outcomes = await Promise.all(
    declared.map((statement) =>
      verifyVariableStatement(
        verified,
        environmentId,
        statement,
        `declared variable ${displayText(statement.variableId)}'s meta statement`,
      ),
    ),
  );
  const seenIds = new Set<string>();
  const values: VerifiedVariableStatement[] = [];
  for (const [index, statement] of declared.entries()) {
    if (statement.environmentId !== environmentId) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Declared variable ${displayText(statement.variableId)} has statement coordinates that do not match the requested context (possible renaming or transplantation)`,
      };
    }
    if (seenIds.has(statement.variableId) || activeIds.has(statement.variableId)) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Duplicate variable IDs within one response (an inconsistent server response): ${statement.variableId}`,
      };
    }
    seenIds.add(statement.variableId);
    if (statement.status !== "declared") {
      // An active appearing here = the value of a verified active
      // statement is missing from the value-bearing response (a value
      // omission, G6 — §6.3's value-distribution requirement). An
      // infiltrating deleted is also refused
      return {
        kind: "rejected",
        evidence: true,
        message:
          statement.status === "active"
            ? `Variable ${displayText(statement.variableId)} has a verified active statement, but the value-bearing response carries no value for it (a value omission — CRYPTO_SPEC §6.3: only declared variables legitimately have no value)`
            : `A deleted statement was served in the declared list: ${displayText(statement.variableId)}`,
      };
    }
    const outcome = outcomes[index]!;
    if (outcome.kind !== "ok") {
      return outcome;
    }
    values.push({
      variableId: statement.variableId,
      name: statement.name,
      status: "declared",
      ...metaEvidenceFields(statement, outcome.value.signedBytesHashHex),
      layoutVersion: outcome.value.layout.layoutVersion,
      schema: outcome.value.layout.schema,
    });
  }
  return { kind: "ok", value: { values, ids: seenIds } };
}

/** Verifying the active variables (including the variableId-duplicate refusal). */
export async function verifyActiveVariables(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  variables: readonly PulledWire[],
): Promise<
  VerifyOutcome<{ readonly values: readonly VerifiedPulledValue[]; readonly ids: Set<string> }>
> {
  // Per-variable verification (statement signature + value signature) is
  // independent, so it runs in parallel; the duplicate-id check and the
  // outcome replay stay in input order so the first reported failure is
  // unchanged (P-5).
  const outcomes = await Promise.all(
    variables.map((variable) => verifyOne(verified, environmentId, variable)),
  );
  const seenIds = new Set<string>();
  const values: VerifiedPulledValue[] = [];
  for (const [index, variable] of variables.entries()) {
    // A duplicate variableId within one response is refused
    // unconditionally (covers the transport shape of equivocation that
    // juxtaposes different signed bytes at the same coordinates — ruling G)
    if (seenIds.has(variable.variableId)) {
      return {
        kind: "rejected",
        evidence: true,
        message: `Duplicate variable IDs within one response (an inconsistent server response): ${variable.variableId}`,
      };
    }
    seenIds.add(variable.variableId);
    const outcome = outcomes[index]!;
    if (outcome.kind !== "ok") {
      return outcome;
    }
    values.push(outcome.value);
  }
  return { kind: "ok", value: { values, ids: seenIds } };
}
