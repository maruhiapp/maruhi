// Server-side verification of meta statements (the AUTH_SPEC §12-5 meta rules = CRYPTO_SPEC §4.2 / §6.4).

import { cryptoEffect } from "@maruhi/core";
import type {
  ChainHistoryIndex,
  MetaInvalidReason,
  MetaPredecessor,
  MetaStatementTarget,
  MetaVariableSchema,
} from "@maruhi/crypto";
import { SUPPORTED_META_LAYOUT_VERSIONS, verifyDistributedMetaStatement } from "@maruhi/crypto";
import { Effect } from "effect";

import { catchCryptoErrors } from "../crypto-catch.ts";
import { MAX_SCHEMA_DESCRIPTION_CODEPOINTS, MAX_VERSIONS_PER_VARIABLE } from "../policy.ts";
import { metaVersionsExceeded } from "../quotas.ts";
import type {
  DataRejectedError,
  MemberWithDevice,
  MetaStatementInput,
  MetaStatementRejectReason,
  SchemaPolicy,
} from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import type { MetaAnchor } from "./data-store.ts";
import { DataStore } from "./data-store.ts";

/**
 * Mapping from crypto's detailed reasons to wire reasons (the same provisional
 * ruling C convention as the value signature's VALUE_REJECT_REASONS — share the
 * three vocabularies and return an independent reason code only for
 * layout-regression, whose error name the spec states explicitly. §12-5).
 * Exhaustiveness is statically enforced by the Record type.
 */
const META_REJECT_REASONS: Readonly<Record<MetaInvalidReason, MetaStatementRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "author-unknown": "chain-head-state-mismatch",
  "author-not-member-at-head": "chain-head-state-mismatch",
  "author-key-mismatch-at-head": "chain-head-state-mismatch",
  "author-role-insufficient-at-head": "chain-head-state-mismatch",
  // §6.3's 3′ (2026-09-14 ES): author out of scope at the declared head (same class as insufficient role)
  "author-environment-out-of-scope-at-head": "chain-head-state-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  "revived-after-delete": "chain-head-state-mismatch",
  // The §4.2 layout v2 transition (active → declared) folds into state-mismatch
  // (same transition class as revived-after-delete — the spec gives no dedicated error name)
  "declared-after-active": "chain-head-state-mismatch",
  // Layout monotonicity (a v1 successor on a v2 variable) is an error name the spec states explicitly (§12-5)
  "layout-regression": "layout-regression",
};

/**
 * Wire MetaStatementInput → crypto's signed schema fields (the required
 * boolean ↔ "true"/"false" mapping lives in this one place).
 */
function cryptoSchemaOf(statement: MetaStatementInput): MetaVariableSchema | undefined {
  if (statement.schema === undefined) {
    return undefined;
  }
  const maxAge = statement.schema.maxAgeDays;
  return {
    varType: statement.schema.varType,
    required: statement.schema.required ? "true" : "false",
    description: statement.schema.description,
    // Layout v3's max_age_days: "" = no declaration, else the decimal (the
    // LP field representation of CRYPTO_SPEC §4.2)
    ...(maxAge === undefined ? {} : { maxAgeDays: maxAge === null ? "" : String(maxAge) }),
  };
}

/**
 * §12-5 (layout v3 — PF6 R9): the wire carries `maxAgeDays` iff the
 * layout is 3 (null = no declaration). A v3 statement without the field,
 * or a v2 statement with it, is a shape mismatch between the declared
 * layout and the fields — refused as 422 payload-mismatch before the
 * signature (the crypto layer would refuse it too, as InvalidInput; this
 * keeps the honest wording).
 */
const ensureLayoutShape = (
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> => {
  const layout = statementLayoutVersion(statement);
  const present = statement.schema?.maxAgeDays !== undefined;
  return (layout === 3) === present || layout === 1
    ? Effect.void
    : Effect.fail(rejectData({ kind: "payload-mismatch", field: "maxAgeDays" }));
};

/**
 * Acceptance verification of a meta statement (§12-5 items 1-3 + the prev
 * chain). What is checked:
 *
 * 1. The signature is verified with the calling principal's sig key derived
 *    from the chain at acceptance time, and author_user_id also uses the
 *    calling principal (rejects carrying in a statement signed by someone else)
 * 2. The exact pair of the declared head (hash + seq) exists on the chain being
 *    verified
 * 3. The author held the required role at the declared head (only environment
 *    deletion needs admin; everything else member — the §12-3 double check),
 *    and the bound key then equals the key at acceptance time
 * 4. metaVersion 1 has an empty prev; > 1 matches the signed-bytes hash of the
 *    stored immediately-preceding statement, and is rejected if the predecessor
 *    is deleted (§4.2 — re-activation is forbidden)
 *
 * Epoch consistency (item 4 of the value §12-5) does not exist for meta (no
 * epoch anchor — §4.2. The environment's existence is not checked either —
 * compatibility with the §12-4 composite bundling form).
 * The coordinates (project / environment / variable) are reconstructed from
 * server-side values (genesis hash, URL, storage location) — never assembled
 * from the wire's declared values (§12-5).
 *
 * On success, returns the server-recomputed signed_bytes hash (written to the
 * stored row).
 */
export const ensureMetaStatementSignature = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly target: MetaStatementTarget;
  readonly history: ChainHistoryIndex;
  readonly member: MemberWithDevice;
  readonly statement: MetaStatementInput;
  /** When metaVersion > 1, the anchor of the stored previous statement (fetched by the caller). */
  readonly predecessor?: MetaPredecessor | undefined;
}) =>
  Effect.gen(function* () {
    yield* ensureLayoutShape(input.statement);
    const verified = yield* catchCryptoErrors(
      cryptoEffect(() =>
        verifyDistributedMetaStatement({
          history: input.history,
          context: {
            suite: input.statement.suite,
            projectId: input.projectId,
            environmentId: input.environmentId,
            target: input.target,
            name: input.statement.name,
            status: input.statement.status,
            // The layout v2 carrier field (§12-2 — omitted = 1). Selects which
            // layout's signed_bytes to recompute (ruling CR)
            layoutVersion: input.statement.layoutVersion,
            schema: cryptoSchemaOf(input.statement),
            metaVersion: input.statement.metaVersion,
            prevMetaSigHashHex: input.statement.prevMetaSigHashHex,
            // author = the calling principal (§12-5 item 1). The bound-key match
            // between the verification key and head time is checked by
            // verifyDistributedMetaStatement via the FP (chain-derived member at acceptance time)
            authorUserId: input.member.userId,
            chainHeadHashHex: input.statement.chainHeadHashHex,
            chainHeadSeq: input.statement.chainHeadSeq,
          },
          authorKeyFingerprintHex: input.member.keyFingerprintHex,
          signatureHex: input.statement.signatureHex,
          predecessor: input.predecessor,
        }),
      ),
      {
        CryptoMetaStatementInvalid: (error) =>
          rejectData({
            kind: "meta-rejected",
            reason: META_REJECT_REASONS[error.reason],
          }),
        // A declared layoutVersion beyond this server's support range ({1, 2, 3})
        // occurs as the **normal case** of "old server × new client" once this
        // revision puts layoutVersion on the wire (ruling CR). The primary check is
        // ensureSupportedLayout at the head of each acceptance path; this is the
        // fail-closed second line of defense (even if a new acceptance path drops
        // the head check, it must not become defect = a 500 indistinguishable from
        // a tamper warning)
        CryptoUnsupportedMetaLayout: () =>
          rejectData({ kind: "meta-rejected", reason: "unsupported-layout" }),
        // Every other kind is unreachable (InvalidInput / KeyImportFailed with
        // a Schema-validated wire plus a key derived from a verified chain;
        // the rest are never returned by this operation): an implementation
        // bug = defect; the error value contains no secrets
        CryptoInvalidInput: "die",
        CryptoKeyImport: "die",
        CryptoKeyExport: "die",
        CryptoEncrypt: "die",
        CryptoDecrypt: "die",
        CryptoDekWrap: "die",
        CryptoDekUnwrap: "die",
        CryptoSign: "die",
        CryptoDekWrapSignature: "die",
        CryptoInviteAcceptSignature: "die",
        CryptoInviteLinkSignature: "die",
        CryptoInviteIssueSignature: "die",
        CryptoDekCommitment: "die",
        CryptoValueInvalid: "die",
        CryptoEnvManifestInvalid: "die",
        CryptoHeadAttestationInvalid: "die",
        ChainInvalid: "die",
      },
    );
    return verified.signedBytesHashHex;
  });

/**
 * §12-1: a name that is not in NFC normal form gets a 422. The server only
 * checks and never normalizes (compatibility with byte-exact signatures — the
 * entity that normalizes is the client, before signing).
 */
export const ensureNfcName = (name: string): Effect.Effect<void, DataRejectedError> =>
  name.normalize("NFC") === name ? Effect.void : Effect.fail(rejectData({ kind: "name-not-nfc" }));

/**
 * A statement's effective layout (wire convention: omitted = 1 — §12-2).
 */
export const statementLayoutVersion = (statement: MetaStatementInput): number =>
  statement.layoutVersion ?? 1;

/**
 * Support-range check for the declared layoutVersion (ruling CR — §12-2 /
 * CRYPTO_SPEC §4.2). Call it **before every other v2-family acceptance check**:
 * for an unsupported layout (v4+ — the normal case of "old server × new
 * client"), the schemaPolicy gate, schema-locked check, and the
 * delete-statement predecessor match are in principle undefinable, and
 * returning those errors first would be misleading in a "fix the policy and it
 * passes" direction. Always return the honest update-required =
 * `unsupported-layout` first. (The same check inside signature verification —
 * crypto's UnsupportedMetaLayout — remains as the fail-closed second line of
 * defense.)
 */
export const ensureSupportedLayout = (
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  SUPPORTED_META_LAYOUT_VERSIONS.includes(statementLayoutVersion(statement))
    ? Effect.void
    : Effect.fail(rejectData({ kind: "meta-rejected", reason: "unsupported-layout" }));

/**
 * §12-8: acceptance check for schema descriptions — at most 1024 code points,
 * no control characters (Unicode category Cc — includes newline, tab, and the
 * ANSI escape ESC). NFC normalization is not required (not an identifier and
 * never used for matching — an intentional difference from name). v1
 * statements (no schema fields) are out of scope. This check is acceptance
 * policy and does not bind what a malicious server distributes (the client's
 * display is always neutralized independently).
 */
export const ensureDescriptionPolicy = (
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> => {
  if (statement.schema === undefined) {
    return Effect.void;
  }
  const description = statement.schema.description;
  if (/\p{Cc}/u.test(description)) {
    return Effect.fail(rejectData({ kind: "description-rejected", reason: "control-characters" }));
  }
  // The limit counts Unicode code points (not UTF-16 code units — §12-8)
  if ([...description].length > MAX_SCHEMA_DESCRIPTION_CODEPOINTS) {
    return Effect.fail(rejectData({ kind: "description-rejected", reason: "too-long" }));
  }
  return Effect.void;
};

/**
 * §12-11 / §12-5 enablement gate: a project whose schemaPolicy is disabled
 * rejects with 422 the **new adoption** of layout v2 (creating a v2 statement
 * at metaVersion 1, and reissuing as v2 a variable whose previous statement is
 * v1). Continuation statements on a variable whose predecessor is already v2
 * (delete, activation, rename, schema reissue) are accepted regardless of the
 * policy (reversibility — downgrading does not freeze the lifecycle of existing
 * v2 variables). v1 statements are accepted regardless of the policy, as
 * before. The decision uses the policy at acceptance time (the caller reads it
 * inside the project DO's serialization).
 */
export const ensureSchemaPolicyAllowsLayout = (input: {
  readonly schemaPolicy: SchemaPolicy;
  readonly statement: MetaStatementInput;
  /** Effective layout of the previous statement (pass 1 for creation = no predecessor). */
  readonly predecessorLayoutVersion: number;
}): Effect.Effect<void, DataRejectedError> =>
  input.schemaPolicy === "disabled" &&
  statementLayoutVersion(input.statement) >= 2 &&
  input.predecessorLayoutVersion === 1
    ? Effect.fail(rejectData({ kind: "schema-policy-rejected", reason: "schema-policy-disabled" }))
    : Effect.void;

/**
 * §12-5: a delete statement's schema fields and layout must match the previous
 * statement byte-exactly (the acceptance check for the same convention as
 * name's "preserve the previous active name" — the crypto layer intentionally
 * does not check this; without it, a validly-signed modified deletion
 * [status = deleted with rewritten schema fields] would be accepted). A
 * mismatch is rejected with the same payload-mismatch as name (with the
 * mismatched field name).
 */
function deletePreservationMismatch(
  anchor: MetaAnchor,
  statement: MetaStatementInput,
): string | null {
  if (statementLayoutVersion(statement) !== anchor.layoutVersion) {
    return "layoutVersion";
  }
  if (anchor.schema === null || statement.schema === undefined) {
    // Layout already matched: only both-v1 (no schema fields) reaches here
    return null;
  }
  const stored = anchor.schema;
  const declared = statement.schema;
  // Each schema field compared in turn; the first difference names the field
  const comparisons: readonly (readonly [string, boolean])[] = [
    ["varType", declared.varType === stored.varType],
    ["required", declared.required === stored.required],
    ["description", declared.description === stored.description],
    ["maxAgeDays", (declared.maxAgeDays ?? null) === (stored.maxAgeDays ?? null)],
  ];
  return comparisons.find(([, same]) => !same)?.[0] ?? null;
}

/** CAS on metaVersion (§12-5): only declared == latest + 1. The 409 returns the latest number only. */
export const ensureMetaCas = (
  latestMetaVersion: number,
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  statement.metaVersion === latestMetaVersion + 1
    ? Effect.void
    : Effect.fail(
        rejectData({ kind: "meta-version-conflict", currentMetaVersion: latestMetaVersion }),
      );

const ensureMetaQuota = (
  latestMetaVersion: number,
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  metaVersionsExceeded(latestMetaVersion, statement.status)
    ? Effect.fail(
        rejectData({
          kind: "limit-exceeded",
          resource: "meta-versions",
          limit: MAX_VERSIONS_PER_VARIABLE,
        }),
      )
    : Effect.void;

/**
 * The meta acceptance pipeline shared by rename / schema reissue / delete /
 * activation (§12-5): metaVersion bound → CAS (409 returns the latest number
 * only) → fetch the stored predecessor statement's anchor (it always exists
 * after CAS passes — absence is a defect) → acceptance-surface v2 checks (the
 * schemaPolicy enablement gate, the description acceptance policy, the delete
 * statement's schema-field/layout predecessor match) → signature verification
 * (predecessor included — prev chaining, rejecting re-statement after delete,
 * transition rules, layout monotonicity).
 * On success, returns the server-recomputed signed_bytes hash.
 */
export const acceptMetaStatement = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly target: MetaStatementTarget;
  readonly latestMetaVersion: number;
  readonly history: ChainHistoryIndex;
  readonly member: MemberWithDevice;
  readonly statement: MetaStatementInput;
  /**
   * schemaPolicy at acceptance time (variable statements only — the caller
   * reads it under the DO permit; environment statements are not v2 targets, so
   * it is not passed for them).
   */
  readonly schemaPolicy?: SchemaPolicy;
}) =>
  Effect.gen(function* () {
    // The support-range check runs first (see the ensureSupportedLayout doc — ruling CR)
    yield* ensureSupportedLayout(input.statement);
    yield* ensureMetaQuota(input.latestMetaVersion, input.statement);
    yield* ensureMetaCas(input.latestMetaVersion, input.statement);
    const store = yield* DataStore;
    const anchor =
      input.target.kind === "variable"
        ? yield* store.variableMetaAnchor(
            input.environmentId,
            input.target.variableId,
            input.latestMetaVersion,
          )
        : yield* store.environmentMetaAnchor(input.environmentId, input.latestMetaVersion);
    if (anchor === null) {
      return yield* Effect.die(new Error("meta predecessor row missing after CAS acceptance"));
    }
    // Enablement gate (§12-11): reject v2 reissue of a v1 variable while
    // disabled (continuation statements whose predecessor is v2 pass regardless
    // of the policy)
    if (input.schemaPolicy !== undefined) {
      yield* ensureSchemaPolicyAllowsLayout({
        schemaPolicy: input.schemaPolicy,
        statement: input.statement,
        predecessorLayoutVersion: anchor.layoutVersion,
      });
    }
    if (input.target.kind === "variable" && input.statement.status === "deleted") {
      // The delete statement's schema fields and layout must match the
      // predecessor (§12-5). The description acceptance policy does **not**
      // apply to deletes: the delete rule is byte-exact preservation of the
      // stored value, and that value was already checked at acceptance.
      // Applying it would make existing v2 variables undeletable after a
      // self-host lowers the limit (a collision with §12-8's "limits never
      // block deletion" principle. This also removes the path where an
      // out-of-contract description-rejected would surface as a 500: a
      // modified description is caught first by this check's payload-mismatch)
      const field = deletePreservationMismatch(anchor, input.statement);
      if (field !== null) {
        return yield* rejectData({ kind: "payload-mismatch", field });
      }
    } else {
      // The description acceptance policy (§12-8 — v1 statements are out of scope)
      yield* ensureDescriptionPolicy(input.statement);
    }
    return yield* ensureMetaStatementSignature({
      projectId: input.projectId,
      environmentId: input.environmentId,
      target: input.target,
      history: input.history,
      member: input.member,
      statement: input.statement,
      // The anchor's stored real values (the layout_version column — input to
      // the layout-monotonicity check. MetaPredecessor.layoutVersion is a
      // mandatory fail-closed field)
      predecessor: {
        signedBytesHashHex: anchor.signedBytesHashHex,
        status: anchor.status,
        layoutVersion: anchor.layoutVersion,
      },
    });
  });
