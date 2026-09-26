// Verification of distributed values and metadata statements (CRYPTO_SPEC
// §6.3).
//
// Before decryption or name resolution, every value's §4.1 value signature
// and the §4.2 meta-statements of the environment and all variables
// (including deleted ones) are verified against the verified chain history.
// The expected coordinates are assembled locally without trusting the
// claimed values: projectId = the verified genesis hash, environmentId = the
// ID used in the request, variableId = the pull response's outer metadata.
// writer / author are the distributed user_id + key FP (matched against the
// chain history). Only names that passed statement verification are trusted
// (§12-2 — the bare name snapshot is gone from the wire).
//
// A future head (declared seq > own view's head), on a value or a
// statement, is not refused immediately: re-sync **exactly once**, pass the
// extension check (sync.ts's ensureExtensionOf), and re-verify everything
// against the new view (bounded — §6.3-2b).
//
// When several same-named active statements in one environment pass
// verification (server equivocation), resolution is refused (§4.2). A
// distributed non-NFC name is a warning (SHOULD — §12-1; byte-exact
// matching never mis-resolves, but the coexistence of visually identical
// names must not be invisible). An active juxtaposed onto an already
// deleted variableId (the transport shape of an unauthorized undeletion) is
// refused.
//
// The latest-only limitation (ruling B): pull carries only the newest
// version, so there is no predecessor — a value's prev-existence match and
// epoch non-decrease, and meta's prev-existence match and re-activation
// after deletion cannot be checked here (shape checks only). Never pretend
// they were checked — detection via the persistent floor is floor-check.ts's
// domain. **Because meta carries no epoch anchor, an injection onto an
// advanced meta_version is not detected even with a floor** (the known
// leftover of §14.3-5).

import type {
  CheckpointValueSnapshot,
  DistributedEncryptedPayload,
  DistributedEnvironmentManifest,
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
  RecipientDek,
  SchemaPolicy,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { MetaStatementContext, MetaVariableSchema } from "@maruhi/crypto";
import { verifyDistributedMetaStatement, verifyDistributedValue } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { checkCheckpointIntegrity } from "./checkpoint-integrity.ts";
import { requireChainEnvironment } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError, evidenceError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import {
  buildEnvironmentFloor,
  checkEnvironmentMetadataPull,
  checkEnvironmentPull,
  type FloorHandle,
  type VerifiedMetaEvidence,
  type VerifiedPullSnapshot,
  type VerifiedSchemaFields,
  type VerifiedTombstone,
  type VerifiedVariableStatement,
} from "./floor-check.ts";
import { formatFloorViolation } from "./floor-evidence.ts";
import type { ManifestFloor } from "./floor.ts";
import {
  type ManifestDigestEntry,
  missingManifestMessage,
  type VerifiedManifest,
  verifyDistributedManifest,
} from "./manifest.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

/** One pulled variable whose write signature and statement passed §6.3. */
export interface VerifiedPulledValue {
  readonly variableId: string;
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
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
  /** The verified statement signature and its attribution (same). */
  readonly metaSignatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
  /** The statement's wire layoutVersion (omitted = 1 — §12-2). */
  readonly layoutVersion: number;
  /** The schema column of layout v2 (null for v1. The type is a declaration — advisory §14.3-7). */
  readonly schema: VerifiedSchemaFields | null;
}

/** A bulk pull whose values and statements all passed verification (§12-7 / §6.3). */
export interface VerifiedEnvironmentPull {
  /** The view used for verification (may have advanced via a future head's bounded resync). */
  readonly verified: VerifiedProject;
  readonly variables: readonly VerifiedPulledValue[];
  /**
   * Verified declared statements (valueless declarations — §4.2 layout v2).
   * declared is the only legitimate valueless state (CRYPTO_SPEC §6.3's
   * value-distribution requirement).
   */
  readonly declared: readonly VerifiedVariableStatement[];
  /** Verified tombstones (digest material for manifest issuance — §4.3). */
  readonly tombstones: readonly VerifiedTombstone[];
  /** The verified environment meta-statement (the envMeta material for manifest issuance). */
  readonly environment: VerifiedMetaEvidence;
  /**
   * The verified manifest (§4.3). null only when the migration path
   * (allowMissingManifest) permitted the omission — an omission on the
   * normal path is already refused (§6.3).
   */
  readonly manifest: VerifiedManifest | null;
  /** The wraps addressed to me (verification is the §5.1 / §5.2 path of deks.ts). */
  readonly deks: readonly RecipientDek[];
  /** SHOULD warnings such as a distributed non-NFC name (displayed by the caller). */
  readonly warnings: readonly string[];
}

/** One pulled variable on the wire (statement + value — AUTH_SPEC §12-7 / §14-2). */
export interface PulledWire {
  readonly variableId: string;
  readonly statement: DistributedVariableMetaStatement;
  readonly value: DistributedEncryptedPayload;
}

type VerifyOutcome<T> =
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
  environmentId: string,
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
 * UnsupportedMetaLayout (a layoutVersion beyond the supported range
 * {1, 2} — checked by crypto **before** the signature verification) is an
 * honest breaking mode meaning "the client needs an update", and is not
 * collapsed into the tampering-suspect wording (CRYPTO_SPEC §4.2 — ruling
 * CR).
 */
/** Whether a failure can be classified as future (the bounded-resync entry) (§6.3-2b). */
function isFutureFailure(
  verified: VerifiedProject,
  chainHeadSeq: number,
  error: { readonly kind: string; readonly reason?: string },
): boolean {
  if (error.kind !== "ValueInvalid" && error.kind !== "MetaStatementInvalid") {
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
  error: { readonly kind: string; readonly reason?: string; readonly layoutVersion?: number },
): VerifyOutcome<T> {
  if (error.kind === "UnsupportedMetaLayout") {
    return {
      kind: "rejected",
      // An honest breaking mode (the client needs an update) — not evidence of tampering (ruling CR)
      evidence: false,
      message: `${label} uses statement layout version ${error.layoutVersion ?? "(unknown)"}, which this CLI does not support (supported: 1, 2). This is not a tampering indication — update the maruhi CLI (CRYPTO_SPEC §4.2)`,
    };
  }
  if (isFutureFailure(verified, chainHeadSeq, error)) {
    return { kind: "future" };
  }
  return {
    kind: "rejected",
    evidence: true,
    message: `Verification of ${label} failed (reason=${error.reason ?? error.kind}). It may have been replaced or forged by the server`,
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
 * Interpreting a variable statement's wire v2 fields (§12-2): a v1 has all
 * 4 fields absent, a v2 has all 4 present. A partial presence is a shape an
 * honest server's response never has (the server guarantees the join of
 * stored rows — §12-2), so it is refused. layoutVersion's wire type is an
 * integer with no fixed upper bound (explicit values ≥ 2), and the
 * supported-range ({1, 2}) check happens in the crypto layer
 * (metaContextRejection) before the signature verification — the range is
 * not checked here (don't collapse a v3 into a Schema / shape error).
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
  return {
    layoutVersion: statement.layoutVersion,
    schema: {
      varType: statement.varType,
      required: statement.required,
      description: statement.description,
    },
  };
}

/** The refusal message for a distribution carrying a partial v2 field set (§12-2's all-or-nothing rule). */
function partialLayoutMessage(label: string): string {
  return `${label} carries only part of the layout-v2 field set (layoutVersion / varType / required / description must be all present or all absent — an inconsistent server response)`;
}

/** The v2 fields passed to crypto's signed context (required in the signature convention's string form — §4.2). */
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
  };
  return { layoutVersion: layout.layoutVersion, schema };
}

/**
 * The composite verification of a statement (§6.3). The context is
 * assembled locally from the expected coordinates. A variable statement's
 * v2 fields (layout) are interpreted from the wire by the caller and passed
 * in (an environment meta stays v1 — §4.2 — and carries no layout).
 */
async function verifyStatement(
  verified: VerifiedProject,
  environmentId: string,
  target: MetaStatementContext["target"],
  statement: DistributedVariableMetaStatement | DistributedEnvironmentMetaStatement,
  label: string,
  layout?: WireStatementLayout | null,
): Promise<VerifyOutcome<{ readonly signedBytesHashHex: string }>> {
  const result = await verifyDistributedMetaStatement({
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
  });
  if (!result.ok) {
    return failureOutcome(verified, label, statement.chainHeadSeq, result.error);
  }
  return { kind: "ok", value: result.value };
}

/**
 * Verifying a variable statement (the entry of verifyStatement with the
 * wire v2 interpretation). A partial v2 field set is refused here; on
 * success the layout (for display, carry-over, digest material) is also
 * returned.
 */
async function verifyVariableStatement(
  verified: VerifiedProject,
  environmentId: string,
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
  environmentId: string,
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
  const result = await verifyDistributedValue({
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
  });
  if (!result.ok) {
    return failureOutcome(
      verified,
      `variable ${displayText(statement.name)}'s value signature`,
      payload.chainHeadSeq,
      result.error,
    );
  }
  return {
    kind: "ok",
    value: {
      variableId: variable.variableId,
      name: statement.name,
      version: payload.aad.version,
      epoch: payload.aad.epoch,
      nonceHex: payload.nonceHex,
      ciphertextHex: payload.ciphertextHex,
      prevValueSigHashHex: payload.prevValueSigHashHex,
      signedBytesHashHex: result.value.signedBytesHashHex,
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
  };
}

interface PullWire {
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly PulledWire[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  /**
   * The latest statements of declared variables (§12-7 — no value or
   * version exists). Absent = no declared (an optionalKey doubling as
   * decode compatibility with old server responses).
   */
  readonly declaredVariables?: readonly DistributedVariableMetaStatement[] | undefined;
  /** The latest manifest (§12-7 — omission is unconditionally refused, §6.3. optional only for the migration's transitional state). */
  readonly manifest?: DistributedEnvironmentManifest | undefined;
  /**
   * The enumeration of value snapshots at the checkpoint (§12-7 — rule
   * 2's material. An omission on an environment with a baseline is refused
   * by checkpoint-integrity.ts).
   */
  readonly checkpointSnapshot?: CheckpointValueSnapshot | undefined;
}

/** Verifying the environment's own statement (including that it is active). Returns the evidence material. */
async function verifyEnvironmentStatement(
  verified: VerifiedProject,
  environmentId: string,
  statement: DistributedEnvironmentMetaStatement,
): Promise<VerifyOutcome<VerifiedMetaEvidence>> {
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
  if (statement.status !== "active") {
    return {
      kind: "rejected",
      evidence: true,
      message: `Environment ${environmentId} was served a deleted statement (distribution of a deleted environment — an inconsistent server response)`,
    };
  }
  return {
    kind: "ok",
    value: {
      status: "active",
      ...metaEvidenceFields(statement, result.value.signedBytesHashHex),
    },
  };
}

/** Verifying a deleted variable's tombstone statement (a juxtaposition with the active / declared side = the transport shape of an unauthorized undeletion, also refused). */
async function verifyDeletedStatements(
  verified: VerifiedProject,
  environmentId: string,
  deleted: readonly DistributedVariableMetaStatement[],
  liveIds: ReadonlySet<string>,
): Promise<VerifyOutcome<readonly VerifiedTombstone[]>> {
  const seen = new Set<string>();
  const tombstones: VerifiedTombstone[] = [];
  for (const statement of deleted) {
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
    const result = await verifyVariableStatement(
      verified,
      environmentId,
      statement,
      `deleted variable ${displayText(statement.variableId)}'s meta statement`,
    );
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
function checkVerifiedNames(
  values: readonly { readonly variableId: string; readonly name: string }[],
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
async function verifyVariableStatements(
  verified: VerifiedProject,
  environmentId: string,
  statements: readonly DistributedVariableMetaStatement[],
): Promise<
  VerifyOutcome<{
    readonly values: readonly VerifiedVariableStatement[];
    readonly ids: Set<string>;
  }>
> {
  const seenIds = new Set<string>();
  const values: VerifiedVariableStatement[] = [];
  for (const statement of statements) {
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
    const outcome = await verifyVariableStatement(
      verified,
      environmentId,
      statement,
      `variable ${displayText(statement.variableId)}'s meta statement`,
    );
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
async function verifyDeclaredStatements(
  verified: VerifiedProject,
  environmentId: string,
  declared: readonly DistributedVariableMetaStatement[],
  activeIds: ReadonlySet<string>,
): Promise<
  VerifyOutcome<{
    readonly values: readonly VerifiedVariableStatement[];
    readonly ids: Set<string>;
  }>
> {
  const seenIds = new Set<string>();
  const values: VerifiedVariableStatement[] = [];
  for (const statement of declared) {
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
    const outcome = await verifyVariableStatement(
      verified,
      environmentId,
      statement,
      `declared variable ${displayText(statement.variableId)}'s meta statement`,
    );
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
async function verifyActiveVariables(
  verified: VerifiedProject,
  environmentId: string,
  variables: readonly PulledWire[],
): Promise<
  VerifyOutcome<{ readonly values: readonly VerifiedPulledValue[]; readonly ids: Set<string> }>
> {
  const seenIds = new Set<string>();
  const values: VerifiedPulledValue[] = [];
  for (const variable of variables) {
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
    const outcome = await verifyOne(verified, environmentId, variable);
    if (outcome.kind !== "ok") {
      return outcome;
    }
    values.push(outcome.value);
  }
  return { kind: "ok", value: { values, ids: seenIds } };
}

/** The result of running a verification stage (rejected is already folded into the failure channel — the 2 values future | ok). */
type StageResult<T> = { readonly kind: "ok"; readonly value: T } | { readonly kind: "future" };

/**
 * The shared wrapper of a verification stage: folds a crypto-execution
 * failure into a CliError and a rejected into the failure channel (each
 * stage's leftover is the 2 values future | ok).
 */
function verifyStage<T>(
  run: () => Promise<VerifyOutcome<T>>,
  description: string,
): Effect.Effect<StageResult<T>, CliError> {
  return Effect.gen(function* () {
    const outcome = yield* Effect.tryPromise({
      try: run,
      catch: () => cliError(`${description} failed to run (crypto error)`),
    });
    if (outcome.kind === "rejected") {
      // Signed distributed data that fails verification = evidence (a
      // re-run does not resolve it — errors.ts's definition of evidence; it
      // must not be folded into cleanup warnings). The exception is the
      // honest breaking mode (UnsupportedMetaLayout)
      return yield* Effect.fail(
        outcome.evidence ? evidenceError(outcome.message) : cliError(outcome.message),
      );
    }
    return outcome.kind === "future"
      ? ({ kind: "future" } as const)
      : ({ kind: "ok", value: outcome.value } as const);
  });
}

/**
 * The manifest stage (§4.3 / §6.3): omission = unconditional refusal (the
 * only exception is the migration path's allowMissingManifest —
 * manifest.ts's module comment). When distributed, the digest is
 * recomputed from every verified statement (tombstones included) and
 * compared.
 */
function verifyManifestStage(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly manifest: DistributedEnvironmentManifest | undefined;
  readonly allowMissingManifest: boolean;
  readonly entries: readonly ManifestDigestEntry[];
  readonly environment: VerifiedMetaEvidence;
  /** The floor's manifest record (the predecessor of the adjacent prev verification — M1-A1. null when there is no floor). */
  readonly floorManifest: ManifestFloor | null;
}): Effect.Effect<StageResult<VerifiedManifest | null>, CliError> {
  const wireManifest = input.manifest;
  if (wireManifest === undefined) {
    if (!input.allowMissingManifest) {
      return Effect.fail(cliError(missingManifestMessage(input.environmentId)));
    }
    // The migration allowance (--init-manifest) exists for "an environment
    // whose manifest was never initialized". An environment that has a
    // baseline checkpoint on the verified chain always carries a manifest
    // (the checkpoint tuple binds manifest_version — §6.2 / §12-4), so its
    // omission is refused as evidence of suppression even under the
    // migration operation (the chain-derived version of refusing an
    // omission after the floor's manifest record is established — §6.3)
    if (input.verified.history.latestCheckpointFor(input.environmentId) !== undefined) {
      return Effect.fail(
        evidenceError(
          `The server did not distribute an environment manifest for ${input.environmentId}, although the verified chain carries a checkpoint binding one (manifest suppression — CRYPTO_SPEC §6.3). The migration allowance does not apply to a checkpointed environment`,
        ),
      );
    }
    return Effect.succeed({ kind: "ok", value: null } as const);
  }
  return verifyStage(
    () =>
      // A manifest refusal is a contradiction between signed distributed
      // data = evidence (manifest.ts's result type carries no evidence, so
      // it is attached here — there is no honest breaking mode at this
      // stage)
      verifyDistributedManifest({
        verified: input.verified,
        environmentId: input.environmentId,
        manifest: wireManifest,
        entries: input.entries,
        envMeta: {
          metaVersion: input.environment.metaVersion,
          sigHashHex: input.environment.metaSigHashHex,
        },
        floorManifest: input.floorManifest,
      }).then((outcome) =>
        outcome.kind === "rejected" ? { ...outcome, evidence: true } : outcome,
      ),
    "Environment-manifest verification",
  );
}

/**
 * The shared verification skeleton of a pull response (§6.3): environment
 * statement → the active set (swapped by shape: value-bearing /
 * metadata-only) → the declared set (the declaredVariables of a
 * value-bearing response — empty in metadata-only mode where they are
 * mixed into variables) → tombstones → the name check → **the manifest**
 * (digest recomputation and epoch agreement — §4.3. omission =
 * unconditional refusal; the only exception is the migration path's
 * allowMissingManifest — manifest.ts's module comment). The digest
 * recomputation set is every statement of variables ∪ declared ∪ deleted.
 * A future at any stage makes the whole thing future (the bounded-resync
 * entry).
 */
function verifyAllCommon<T extends { readonly variableId: string; readonly name: string }>(
  verified: VerifiedProject,
  environmentId: string,
  pull: {
    readonly statement: DistributedEnvironmentMetaStatement;
    readonly deletedVariables: readonly DistributedVariableMetaStatement[];
    readonly declaredVariables?: readonly DistributedVariableMetaStatement[] | undefined;
    readonly manifest?: DistributedEnvironmentManifest | undefined;
  },
  verifyActives: () => Promise<
    VerifyOutcome<{ readonly values: readonly T[]; readonly ids: Set<string> }>
  >,
  /** One verified active → the variables_digest entry (the recomputation material of §4.3 (3)). */
  digestEntryOf: (value: T) => ManifestDigestEntry,
  /** True only for the migration path (--init-manifest) — an omission allowance, not a verification relaxation. */
  allowMissingManifest: boolean,
  /** The floor's manifest record (the adjacent prev verification — M1-A1. Paths with no floor pass null). */
  floorManifest: ManifestFloor | null,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedMetaEvidence;
      readonly variables: readonly T[];
      readonly declared: readonly VerifiedVariableStatement[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly manifest: VerifiedManifest | null;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return Effect.gen(function* () {
    const environment = yield* verifyStage(
      () => verifyEnvironmentStatement(verified, environmentId, pull.statement),
      "Environment-statement verification",
    );
    if (environment.kind === "future") {
      return { kind: "future" } as const;
    }
    const actives = yield* verifyStage(
      verifyActives,
      "Variable-statement / value-signature verification",
    );
    if (actives.kind === "future") {
      return { kind: "future" } as const;
    }
    const declared = yield* verifyStage(
      () =>
        verifyDeclaredStatements(
          verified,
          environmentId,
          pull.declaredVariables ?? [],
          actives.value.ids,
        ),
      "Declared-variable-statement verification",
    );
    if (declared.kind === "future") {
      return { kind: "future" } as const;
    }
    const liveIds = new Set([...actives.value.ids, ...declared.value.ids]);
    const deleted = yield* verifyStage(
      () => verifyDeletedStatements(verified, environmentId, pull.deletedVariables, liveIds),
      "Deleted-variable-statement verification",
    );
    if (deleted.kind === "future") {
      return { kind: "future" } as const;
    }
    const warnings: string[] = [];
    const nameFailure = checkVerifiedNames(
      [...actives.value.values, ...declared.value.values],
      warnings,
    );
    if (nameFailure !== null) {
      return yield* Effect.fail(cliError(nameFailure));
    }
    const manifest = yield* verifyManifestStage({
      verified,
      environmentId,
      manifest: pull.manifest,
      allowMissingManifest,
      entries: [
        ...actives.value.values.map(digestEntryOf),
        ...declared.value.values.map((statement) => ({
          variableId: statement.variableId,
          status: "declared" as const,
          metaVersion: statement.metaVersion,
          metaSigHashHex: statement.metaSigHashHex,
        })),
        ...deleted.value.map((tombstone) => ({
          variableId: tombstone.variableId,
          status: "deleted" as const,
          metaVersion: tombstone.metaVersion,
          metaSigHashHex: tombstone.metaSigHashHex,
        })),
      ],
      environment: environment.value,
      floorManifest,
    });
    if (manifest.kind === "future") {
      return { kind: "future" } as const;
    }
    return {
      kind: "ok",
      environment: environment.value,
      variables: actives.value.values,
      declared: declared.value.values,
      tombstones: deleted.value,
      manifest: manifest.value,
      warnings,
    } as const;
  });
}

function verifyAll(
  verified: VerifiedProject,
  environmentId: string,
  pull: PullWire,
  allowMissingManifest: boolean,
  floorManifest: ManifestFloor | null,
  /**
   * The head seq of the view **at the moment the response was fetched**
   * (pull = the fetch-time view, lease = the bundled chain's head). Since
   * the bounded resync's re-verification re-verifies the same response
   * body against the advanced view, distinguishing a benign race where
   * rule 2's baseline is newer than the response needs this
   * (checkpoint-integrity.ts).
   */
  fetchedAtHeadSeq: number,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly snapshot: VerifiedPullSnapshot;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return Effect.gen(function* () {
    const result = yield* verifyAllCommon(
      verified,
      environmentId,
      pull,
      () => verifyActiveVariables(verified, environmentId, pull.variables),
      (value) => ({
        variableId: value.variableId,
        status: "active" as const,
        metaVersion: value.metaVersion,
        metaSigHashHex: value.metaSignedBytesHashHex,
      }),
      allowMissingManifest,
      floorManifest,
    );
    if (result.kind === "future") {
      return { kind: "future" } as const;
    }
    // Rule 2 of checkpoint integrity (§6.3 — the value-carrying path only.
    // metadata-only is out of scope since it carries no values, §12-7). The
    // tombstone deletion explanation assumes the manifest-consistent set,
    // so it sits after the manifest stage (inside verifyAllCommon). A
    // refusal with evidence = a contradiction between verified data and the
    // chain notarization (typed so rotate's endgame classification does not
    // downgrade it to the "a re-run fixes it" guidance). A refusal without
    // evidence = a shape a benign race — the baseline advanced past the
    // fetch-time view — can also explain (a re-pull can resolve it)
    const checkpoint = yield* Effect.tryPromise({
      try: () =>
        checkCheckpointIntegrity({
          history: verified.history,
          environmentId,
          snapshot: pull.checkpointSnapshot,
          variables: result.variables,
          tombstoneIds: new Set(result.tombstones.map((tombstone) => tombstone.variableId)),
          fetchedAtHeadSeq,
        }),
      catch: () => cliError("Checkpoint-integrity verification failed to run (crypto error)"),
    });
    if (checkpoint.kind === "rejected") {
      return yield* Effect.fail(
        checkpoint.evidence ? evidenceError(checkpoint.message) : cliError(checkpoint.message),
      );
    }
    if (checkpoint.kind === "future") {
      return { kind: "future" } as const;
    }
    return {
      kind: "ok",
      snapshot: {
        environment: result.environment,
        variables: result.variables,
        declared: result.declared,
        tombstones: result.tombstones,
        manifest: result.manifest,
      },
      warnings: result.warnings,
    } as const;
  });
}

/**
 * Reconciling meta-op intents against a verified distribution (§6.3 record
 * discipline (ii) — 3-F). If the verified manifest reached or passed the
 * intent's version, the confirmation duty can resolve:
 * - same version, same hash = my issuance is being distributed (accepted)
 * - same version, different hash = my issuance was not stored
 *   (not-accepted — the distributed verified manifest is already joined
 *   into the floor as an observation, so the evidence is not lost)
 * - advanced = the duty fulfilled by observing a verified successor state
 *   (superseded)
 * - the distributed version older than the intent = left unresolved
 *   (carried over to the next reconciliation opportunity)
 */
function resolveMetaIntents(
  floor: FloorHandle,
  manifest: VerifiedManifest | null,
): Effect.Effect<void, CliError> {
  if (manifest === null) {
    return Effect.void;
  }
  return Effect.forEach(
    floor.unresolvedIntents().filter((intent) => intent.op === "meta-op"),
    (intent) => {
      if (manifest.manifestVersion > intent.manifestVersion) {
        return floor.resolveIntent(intent.id, "superseded");
      }
      if (manifest.manifestVersion === intent.manifestVersion) {
        return floor.resolveIntent(
          intent.id,
          manifest.signedBytesHashHex === intent.manifestSigHashHex ? "accepted" : "not-accepted",
        );
      }
      return Effect.void;
    },
    { discard: true },
  );
}

/**
 * The floor check (§6.3's (a)(b)(c)) and the floor commit (the update
 * ordering norm: checks run against the last successful pull's baseline,
 * and the baseline's advance is committed atomically with the variable
 * floors after verification succeeds). Every check compares data that
 * passed signature verification, so a disagreement is non-repudiable
 * evidence and every case is refused (the strong side of §6.3's "reject vs
 * warn").
 *
 * The commit point is the §6.3 verification success (a later wrap
 * verification / decryption failure never rolls the floor back — only
 * signature-verified digests are recorded, and the baseline monotonicity
 * argument is independent of decryption success. The "verification" of "a
 * successful pull (verification included)" is read as §6.3).
 */
function enforceFloor(input: {
  readonly floor: FloorHandle;
  /**
   * The view used to derive the rule (c) baseline. **It must be the view
   * verified before the pull response was fetched**: deriving the baseline
   * from a view newer than the response (after a future head's bounded
   * resync) over-advances the baseline across a rotate that landed between
   * the response generation and the resync, and the next pull would
   * falsely refuse "a legitimate old-epoch latest value after a rotation,
   * before re-encryption completes" (§12-7) (applying §6.3's "never advance
   * the baseline on a chain sync alone" norm to the resync path). With
   * baseline ≤ the epoch at response-generation time, the epoch of every
   * legitimate push accepted later is always ≥ the baseline, so no false
   * rejection.
   */
  readonly baselineView: VerifiedProject;
  /** The view used for verification (the commit value of the floor's chain head). */
  readonly commitView: VerifiedProject;
  readonly environmentId: string;
  readonly snapshot: VerifiedPullSnapshot;
}): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const violation = checkEnvironmentPull(input.floor.current(), input.snapshot);
    if (violation !== null) {
      // Refuse + presentable evidence (coordinates, both signed-bytes
      // hashes, declared heads). A floor violation is a contradiction
      // between properly signed data = evidence (a re-run does not resolve
      // it)
      return yield* Effect.fail(
        evidenceError(
          formatFloorViolation(
            { projectId: input.commitView.projectId, environmentId: input.environmentId },
            violation,
          ),
        ),
      );
    }
    // A distribution that passes verification for an environment absent
    // from the chain stops here (meta carries no epoch anchor, so in an
    // environment with zero variables statement verification alone cannot
    // detect it)
    yield* requireChainEnvironment(input.commitView, input.environmentId);
    // The rule (c) baseline's advance value = the pre-response-fetch
    // view's chain-derived current epoch (§6.2 — the server-claimed
    // currentEpoch is never used)
    const baselineEnvironment = input.baselineView.state.environments.get(input.environmentId);
    if (baselineEnvironment === undefined) {
      // The rare race where the environment was created between the
      // response fetch and the resync: there is no view to derive the
      // baseline from without over-advancing it, so this commit is skipped
      // (established on the next pull. The floor is a SHOULD — the
      // detection material is just established one cycle late; no false
      // detection)
      return;
    }
    yield* input.floor.commitPull(
      buildEnvironmentFloor(baselineEnvironment.currentEpoch, input.snapshot),
      { seq: input.commitView.state.headSeq, hashHex: input.commitView.state.headHashHex },
    );
    // A verified distribution arrived, so reconcile this environment's unresolved meta intents (3-F)
    yield* resolveMetaIntents(input.floor, input.snapshot.manifest);
  });
}

/**
 * The shared skeleton of the pull family (§6.3-2b): fetch → verify →
 * floor check (accept). A future (a declared head beyond the own view =
 * possibly just a stale own chain) at any stage re-syncs **exactly once**,
 * checks that the new view is an extension of the old, then re-verifies
 * everything (bounded. Via the extension check + the prev_hash chain, the
 * advanced view stays consistent with openProject's floor check — every
 * entry at or below the floor's seq matches). A re-verification that is
 * still future is refused with divergedMessage.
 */
function pullWithBoundedResync<TWire, TVerified>(input: {
  readonly verified: VerifiedProject;
  /** The bounded resync on a future head (once). */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly fetch: Effect.Effect<TWire, CliError>;
  readonly verify: (
    view: VerifiedProject,
    wire: TWire,
  ) => Effect.Effect<
    { readonly kind: "ok"; readonly value: TVerified } | { readonly kind: "future" },
    CliError
  >;
  /** The floor check / commit. view = the view used for verification (may have advanced via the resync). */
  readonly accept: (view: VerifiedProject, value: TVerified) => Effect.Effect<void, CliError>;
  readonly divergedMessage: string;
}): Effect.Effect<
  { readonly view: VerifiedProject; readonly wire: TWire; readonly value: TVerified },
  CliError
> {
  return Effect.gen(function* () {
    const wire = yield* input.fetch;
    const first = yield* input.verify(input.verified, wire);
    if (first.kind === "ok") {
      yield* input.accept(input.verified, first.value);
      return { view: input.verified, wire, value: first.value };
    }
    const advanced = yield* resyncExtended(input.resync, input.verified);
    const second = yield* input.verify(advanced, wire);
    if (second.kind === "ok") {
      yield* input.accept(advanced, second.value);
      return { view: advanced, wire, value: second.value };
    }
    // A distribution bound to a chain position that still does not exist after the resync = evidence of a fork / forgery
    return yield* Effect.fail(evidenceError(input.divergedMessage));
  });
}

/**
 * Pulls one environment and verifies every value's write signature and every
 * metadata statement (environment, active variables, tombstones) before
 * anything is decrypted or resolved by name (§6.3 / §12-7). A declared head
 * beyond the local view triggers one bounded re-sync with the extension
 * check; everything is then re-verified against the advanced view.
 */
export function pullVerifiedEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** The bounded resync on a future head (once). */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3). Carries the check (rules (a)(b)(c)) and the atomic commit after verification succeeds. */
  readonly floor: FloorHandle;
  /**
   * Allowing a manifest **omission** (the migration path `maruhi env
   * rotate --init-manifest` only). Verification when distributed is not
   * relaxed. Default false = an omission is unconditionally refused
   * (§6.3).
   */
  readonly allowMissingManifest?: boolean;
}): Effect.Effect<VerifiedEnvironmentPull, CliError> {
  return Effect.map(
    pullWithBoundedResync({
      verified: input.verified,
      resync: input.resync,
      fetch: input.client.variables
        .pull({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
        })
        .pipe(Effect.mapError(toCliError)),
      verify: (view, wire) =>
        verifyAll(
          view,
          input.environmentId,
          wire,
          input.allowMissingManifest === true,
          // The adjacent-version prev verification (M1-A1): the floor's manifest record is passed as the predecessor
          input.floor.current()?.manifest ?? null,
          // The response was fetched under input.verified's view (even on
          // a post-resync re-verification the fetch moment does not change
          // — the baseline for rule 2's benign-race discrimination)
          input.verified.state.headSeq,
        ).pipe(
          Effect.map((result) =>
            result.kind === "future"
              ? result
              : ({
                  kind: "ok",
                  value: { snapshot: result.snapshot, warnings: result.warnings },
                } as const),
          ),
        ),
      accept: (view, value) =>
        enforceFloor({
          floor: input.floor,
          // Verification uses the (possibly advanced) view; the rule (c)
          // baseline is derived from the pre-response-fetch view
          // (enforceFloor's baselineView contract — prevents the baseline
          // over-advancing on a resync)
          baselineView: input.verified,
          commitView: view,
          environmentId: input.environmentId,
          snapshot: value.snapshot,
        }),
      divergedMessage:
        "A value, statement or checkpoint snapshot bound to a chain position that still does not exist on the chain after a re-sync was served (evidence of chain divergence or forgery)",
    }),
    ({ view, wire, value }) => ({
      verified: view,
      variables: value.snapshot.variables,
      declared: value.snapshot.declared,
      tombstones: value.snapshot.tombstones,
      environment: value.snapshot.environment,
      manifest: value.snapshot.manifest,
      deks: wire.deks,
      warnings: value.warnings,
    }),
  );
}

/**
 * Verifies the distribution material of a workload-lease response
 * (CRYPTO_SPEC §9.1 duty (4): environment statement, every active variable's
 * statement + write signature, every tombstone). Same discipline as the bulk
 * pull with exactly one difference: **a declared head beyond the chain is an
 * immediate rejection**, never a bounded re-sync — the chain travels in the
 * same response (AUTH_SPEC §14-2), so "our chain is merely stale" is not an
 * honest explanation; the response contradicts itself.
 *
 * No floor is used: a workload is a first-sync class that holds no floor
 * (§14.3-3), and its main relaxation is the repository anchor (anchor.ts —
 * §6.3 out-of-band anchor (b)).
 */
export function verifyLeaseDistribution(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly wire: PullWire;
}): Effect.Effect<
  {
    readonly variables: readonly VerifiedPulledValue[];
    /** The verified declared (§14-2 — material for ci run's presence check). */
    readonly declared: readonly VerifiedVariableStatement[];
    readonly warnings: readonly string[];
  },
  CliError
> {
  return Effect.gen(function* () {
    // Manifest verification is mandatory (CRYPTO_SPEC §9.1 (5)) and an
    // omission = unconditional refusal (no migration allowance: a workload
    // cannot initialize — initialization is a member's explicit operation,
    // §14). The floor-derived prev check does not apply — a workload is a
    // first-sync class that holds no floor (§14.3-3. session-31 §3 M1-A1's
    // note that leases are out of scope): signature, digest, epoch
    // agreement, and omission refusal stay at the pull's level, and the
    // predecessor is null (the shared verifier's identity). A lease is a
    // self-contained shape where the response bundles the chain — the
    // fetch view = the bundled chain's head itself (the shape where the
    // baseline is newer than the fetch view structurally cannot exist, and
    // rule 2's refusals always classify to the evidence side)
    const result = yield* verifyAll(
      input.verified,
      input.environmentId,
      input.wire,
      false,
      null,
      input.verified.state.headSeq,
    );
    if (result.kind === "future") {
      return yield* Effect.fail(
        cliError(
          "A value, statement or checkpoint snapshot in the lease response is bound to a chain position beyond the chain included in the same response (the response contradicts itself)",
        ),
      );
    }
    // The no-baseline warning (§6.3 SHOULD — a client with no floor warns
    // when it detects that an environment it received a value-carrying
    // distribution for has no baseline checkpoint. Silently tolerating the
    // absence would make "this class's main guarantee = checkpoint
    // integrity is not working" invisible — session-36 ruling V)
    const warnings =
      input.verified.history.latestCheckpointFor(input.environmentId) === undefined
        ? [
            ...result.warnings,
            `No checkpoint on the verified chain covers environment ${input.environmentId}, so checkpoint integrity (rollback and stale-epoch injection detection — CRYPTO_SPEC §6.3) does not protect this response. A project member should issue one with: \`maruhi project checkpoint\``,
          ]
        : result.warnings;
    return {
      variables: result.snapshot.variables,
      declared: result.snapshot.declared,
      warnings,
    };
  });
}

/** The verified response of a metadata-only pull (§12-7's metadata-only mode). */
export interface VerifiedEnvironmentMetadata {
  /** The view used for verification (may have advanced via a future head's bounded resync). */
  readonly verified: VerifiedProject;
  /** The verified statements of all non-deleted variables (active and declared mixed — §12-7). */
  readonly variables: readonly VerifiedVariableStatement[];
  /** Verified tombstones (the only source of name resolution for deleted variables — AUDIT_SPEC §7). */
  readonly tombstones: readonly VerifiedTombstone[];
  /** The verified environment meta-statement (the envMeta material for manifest issuance). */
  readonly environment: VerifiedMetaEvidence;
  /** The verified manifest (omission already refused — no migration tolerance on a metadata-only pull). */
  readonly manifest: VerifiedManifest;
  /**
   * The server-claimed schemaPolicy (§12-7 / §12-11 — advisory). null =
   * an old server (not claiming). **Never an input to a verification
   * rule** — its only use is UX (advance guidance for schema set). An
   * unsigned claimed value, so this structure carrying the verified name
   * marks it advisory explicitly.
   */
  readonly advisorySchemaPolicy: SchemaPolicy | null;
  readonly warnings: readonly string[];
}

/**
 * The issuing material of a meta operation's bundled manifest (§12-5): the
 * previous manifest of a verified metadata pull, the current meta set
 * (active / declared / tombstones included — §4.3's digest covers every
 * statement), and the latest shape of the environment meta.
 */
export interface ManifestIssueBase {
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  };
  /** The current meta set (tombstones included) — the caller appends the new variable's entry per attempt. */
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
}

/**
 * Assembles the manifest issuing material from a verified metadata pull
 * (shared by push's create / activate and schema set / var rm — built from
 * the verified view, not server-claimed values).
 */
export function manifestIssueBaseOf(metadata: VerifiedEnvironmentMetadata): ManifestIssueBase {
  return {
    previous: {
      manifestVersion: metadata.manifest.manifestVersion,
      signedBytesHashHex: metadata.manifest.signedBytesHashHex,
    },
    entries: [
      ...metadata.variables.map((statement) => ({
        variableId: statement.variableId,
        status: statement.status,
        metaVersion: statement.metaVersion,
        metaSigHashHex: statement.metaSigHashHex,
      })),
      ...metadata.tombstones.map((tombstone) => ({
        variableId: tombstone.variableId,
        status: "deleted" as const,
        metaVersion: tombstone.metaVersion,
        metaSigHashHex: tombstone.metaSigHashHex,
      })),
    ],
    envMeta: {
      metaVersion: metadata.environment.metaVersion,
      sigHashHex: metadata.environment.metaSigHashHex,
    },
  };
}

interface MetadataPullWire {
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly DistributedVariableMetaStatement[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  readonly manifest?: DistributedEnvironmentManifest;
  /** The advisory bundling of schemaPolicy (§12-7 — absent = an old server). */
  readonly schemaPolicy?: SchemaPolicy;
}

/** The verified intermediate value of a metadata-only pull (pullWithBoundedResync's TVerified). */
interface VerifiedMetadataValue {
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly manifest: VerifiedManifest;
  readonly warnings: readonly string[];
}

function verifyAllMetadata(
  verified: VerifiedProject,
  environmentId: string,
  pull: MetadataPullWire,
  floorManifest: ManifestFloor | null,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedMetaEvidence;
      readonly variables: readonly VerifiedVariableStatement[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly manifest: VerifiedManifest | null;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return verifyAllCommon(
    verified,
    environmentId,
    // In metadata-only mode declared is mixed into variables (§12-7) — a
    // separate declared list exists only on a value-bearing response
    { ...pull, declaredVariables: [] },
    () => verifyVariableStatements(verified, environmentId, pull.variables),
    (statement) => ({
      variableId: statement.variableId,
      // The active / declared distinction is the verified statement's
      // status (§4.3's entry includes status — pinning "active" would make
      // the digest recomputation of an environment containing a declared
      // always disagree)
      status: statement.status,
      metaVersion: statement.metaVersion,
      metaSigHashHex: statement.metaSigHashHex,
    }),
    false,
    floorManifest,
  );
}

/**
 * The floor check of a metadata-only pull (the valueless shape — only the
 * meta-level rules (a)(b) and omission / undeletion. See
 * checkEnvironmentMetadataPull) and the **environment-level floor commit**
 * (session-31 §3 M1-A3): join the chain head, the environment meta floor,
 * the manifest floor, and the environment-level epoch observation (§6.3
 * coordinate (ii)). **Never fabricate a value floor, never advance the
 * pull baseline (rule (c))** — deriving a value-level baseline from an
 * observation that read no values would falsely refuse a legitimate
 * old-epoch value after a rotation, before re-encryption completes
 * (§6.3's norm).
 */
function enforceMetadataFloor(input: {
  readonly floor: FloorHandle;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly manifest: VerifiedManifest;
}): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const violation = checkEnvironmentMetadataPull(input.floor.current(), {
      environment: input.environment,
      variables: input.variables,
      tombstones: input.tombstones,
      manifest: input.manifest,
    });
    if (violation !== null) {
      // A floor violation is a contradiction between properly signed data = evidence (same as the value pull's enforceFloor)
      return yield* Effect.fail(
        evidenceError(
          formatFloorViolation(
            { projectId: input.verified.projectId, environmentId: input.environmentId },
            violation,
          ),
        ),
      );
    }
    // A distribution that passes verification for an environment absent
    // from the chain stops here (the same phantom-environment check as
    // enforceFloor — meta carries no epoch anchor)
    const environment = yield* requireChainEnvironment(input.verified, input.environmentId);
    // The join of verified facts (§6.3 — a single recording rule, not an
    // enumeration of recording triggers). journal-before-release:
    // persisting the append precedes using the pass or reporting success
    yield* input.floor.commitMetadata(
      {
        observedEpoch: environment.currentEpoch,
        metaVersion: input.environment.metaVersion,
        metaSigHashHex: input.environment.metaSigHashHex,
        manifest: {
          manifestVersion: input.manifest.manifestVersion,
          epoch: input.manifest.epoch,
          manifestSigHashHex: input.manifest.signedBytesHashHex,
        },
      },
      { seq: input.verified.state.headSeq, hashHex: input.verified.state.headHashHex },
    );
    // A verified distribution arrived, so reconcile this environment's unresolved meta intents (3-F)
    yield* resolveMetaIntents(input.floor, input.manifest);
  });
}

/**
 * Pulls only the metadata of one environment (§12-7 metadata-only mode: no
 * values, no DEKs — the server records no `var.read`) and verifies the
 * environment statement, every active variable statement and every tombstone
 * against the verified chain history before any name is trusted (§6.3).
 * Future heads get the same single bounded re-sync as the full pull. Used
 * for name → variableId resolution (push) — a write-path read that must not
 * be recorded as having read values it never received.
 */
export function pullVerifiedEnvironmentMetadata(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** The bounded resync on a future head (once). */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3). The meta-level check + the environment-level commit (enforceMetadataFloor — M1-A3). */
  readonly floor: FloorHandle;
}): Effect.Effect<VerifiedEnvironmentMetadata, CliError> {
  return Effect.map(
    pullWithBoundedResync({
      verified: input.verified,
      resync: input.resync,
      fetch: input.client.variables
        .pullMetadata({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
        })
        .pipe(Effect.mapError(toCliError)),
      verify: (view, wire) =>
        verifyAllMetadata(
          view,
          input.environmentId,
          wire,
          // The adjacent-version prev verification (M1-A1): identical on the metadata-only / value pull paths
          input.floor.current()?.manifest ?? null,
        ).pipe(
          Effect.flatMap(
            (
              result,
            ): Effect.Effect<
              | { readonly kind: "ok"; readonly value: VerifiedMetadataValue }
              | { readonly kind: "future" },
              CliError
            > => {
              if (result.kind === "future") {
                return Effect.succeed({ kind: "future" as const });
              }
              // verifyAllCommon without allowMissing already refused an
              // omission — null is a leftover on the type side
              // (structurally unreachable), so fail it explicitly
              if (result.manifest === null) {
                return Effect.fail(cliError(missingManifestMessage(input.environmentId)));
              }
              return Effect.succeed({
                kind: "ok" as const,
                value: {
                  environment: result.environment,
                  variables: result.variables,
                  tombstones: result.tombstones,
                  manifest: result.manifest,
                  warnings: result.warnings,
                },
              });
            },
          ),
        ),
      accept: (view, value) =>
        enforceMetadataFloor({
          floor: input.floor,
          verified: view,
          environmentId: input.environmentId,
          environment: value.environment,
          variables: value.variables,
          tombstones: value.tombstones,
          manifest: value.manifest,
        }),
      divergedMessage:
        "A statement bound to a head that still does not exist on the chain after a re-sync was served (evidence of chain divergence or forgery)",
    }),
    ({ view, wire, value }) => ({
      verified: view,
      variables: value.variables,
      tombstones: value.tombstones,
      environment: value.environment,
      manifest: value.manifest,
      // advisory (§12-11): an unverified claimed value — UX use only (absent = an old server)
      advisorySchemaPolicy: wire.schemaPolicy ?? null,
      warnings: value.warnings,
    }),
  );
}

/**
 * Returns the set of "verified deleted environments" from an environment
 * list's signed statements (§12-4 — a deletion is also a signed
 * statement). Statements that fail verification, whose coordinates don't
 * match, or whose status is not deleted are not included (fail-closed —
 * the caller keeps them as targets without trusting the deletion; §7 never
 * silently skips on the server's claim alone).
 */
export function verifiedDeletedEnvironments(
  verified: VerifiedProject,
  environments: readonly {
    readonly environmentId: string;
    readonly statement: DistributedEnvironmentMetaStatement;
  }[],
): Effect.Effect<ReadonlySet<string>, CliError> {
  return Effect.tryPromise({
    try: async () => {
      const deleted = new Set<string>();
      for (const environment of environments) {
        const statement = environment.statement;
        if (
          statement.environmentId !== environment.environmentId ||
          statement.status !== "deleted"
        ) {
          continue;
        }
        const outcome = await verifyStatement(
          verified,
          environment.environmentId,
          { kind: "environment" },
          statement,
          `environment ${displayText(environment.environmentId)}'s deletion statement`,
        );
        if (outcome.kind === "ok") {
          deleted.add(environment.environmentId);
        }
      }
      return deleted;
    },
    catch: () => cliError("Environment-statement verification failed"),
  });
}
