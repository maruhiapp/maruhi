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
  // The §4.2 layout v3 transition (active → declared) folds into state-mismatch
  // (same transition class as revived-after-delete — the spec gives no dedicated error name)
  "declared-after-active": "chain-head-state-mismatch",
  // Layout monotonicity (a v1 successor on a v3 variable) is an error name the spec states explicitly (§12-5)
  "layout-regression": "layout-regression",
};

/**
 * Wire MetaStatementInput → crypto's signed schema fields (the required
 * boolean ↔ "true"/"false" mapping lives in this one place). max_age_days
 * is "" = no declaration, else the decimal (the LP field representation of
 * CRYPTO_SPEC §4.2). A missing maxAgeDays never reaches here on layout 3
 * ({@link ensureLayoutShape} refuses it first); any other layout is refused
 * by crypto's layout check before the fields are read.
 */
function cryptoSchemaOf(statement: MetaStatementInput): MetaVariableSchema | undefined {
  if (statement.schema === undefined) {
    return undefined;
  }
  const maxAge = statement.schema.maxAgeDays ?? null;
  return {
    varType: statement.schema.varType,
    required: statement.schema.required ? "true" : "false",
    description: statement.schema.description,
    maxAgeDays: maxAge === null ? "" : String(maxAge),
  };
}

/**
 * §12-5 (layout v3): a v3 statement carries `maxAgeDays` (null = no
 * declaration). A v3 statement without the field is a shape mismatch
 * between the declared layout and the fields — refused as 422
 * payload-mismatch before the signature (the crypto layer would refuse it
 * too, as InvalidInput; this keeps the honest wording).
 */
const ensureLayoutShape = (
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  statementLayoutVersion(statement) !== 3 || statement.schema?.maxAgeDays !== undefined
    ? Effect.void
    : Effect.fail(rejectData({ kind: "payload-mismatch", field: "maxAgeDays" }));

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
export const ensureMetaStatementSignature = Effect.fn("verify-meta.ensureMetaStatementSignature")(
  function* (input: {
    readonly projectId: string;
    readonly environmentId: string;
    readonly target: MetaStatementTarget;
    readonly history: ChainHistoryIndex;
    readonly member: MemberWithDevice;
    readonly statement: MetaStatementInput;
    /** When metaVersion > 1, the anchor of the stored previous statement (fetched by the caller). */
    readonly predecessor?: MetaPredecessor | undefined;
  }) {
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
            // The layout carrier field (§12-2 — omitted = 1). Selects which
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
        // A declared layoutVersion outside this server's support range ({1, 3} —
        // the retired 2, or a later layout as the **normal case** of "old
        // server × new client" — ruling CR). The primary check is
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
  },
);

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
 * CRYPTO_SPEC §4.2). Call it **before every other schema-layout acceptance
 * check**: for an unsupported layout (the retired 2, or v4+ — the normal
 * case of "old server × new client"), the schema-locked check and the
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
 * The lifecycle operation a meta statement performs. Each route fixes it (the
 * wire schema already pins the route's status), and it selects the
 * predecessor-match rule ({@link predecessorMismatch}).
 *
 * - `reissue`: a rename or schema re-issuance (variable or environment)
 * - `activate`: declared → active (the activation composite)
 * - `delete`: a variable or environment deletion
 */
export type MetaOperation = "reissue" | "activate" | "delete";

/**
 * §12-5: a delete statement's name, schema fields and layout must match the
 * previous statement byte-exactly (the crypto layer intentionally does not
 * check this; without it, a validly-signed modified deletion [status =
 * deleted with a rewritten name or schema fields] would be accepted). The
 * first mismatched field is named.
 */
function deletePreservationMismatch(
  anchor: MetaAnchor,
  statement: MetaStatementInput,
): string | null {
  // A deleted statement's name preserves the previous active name (§4.2)
  if (statement.name !== anchor.name) {
    return "name";
  }
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

/**
 * The predecessor-match checks of §12-5, judged against the stored
 * immediately-preceding statement (the anchor). They depend on the
 * predecessor, so {@link acceptMetaStatement} runs them only after the
 * metaVersion CAS: a statement signed over a stale view is a 409 (the
 * client retries over a re-verified view), never a 422 (AUTH_SPEC §12-5's
 * check order). Returns the first mismatched field, or null.
 *
 * - `reissue`: status is unchanged (declared → active is only the
 *   activation composite; active → declared is forbidden)
 * - `activate`: the predecessor is declared (the activation target is only
 *   a declared variable — the value CAS cannot double as that check, since
 *   version N+1 to an active variable would pass it) and the name is
 *   unchanged (activation does not double as a rename: the "name change ⇔
 *   var.renamed row" correspondence stays with the rename path)
 * - `delete`: name, schema fields and layout are preserved
 */
function predecessorMismatch(
  operation: MetaOperation,
  anchor: MetaAnchor,
  statement: MetaStatementInput,
): string | null {
  switch (operation) {
    case "reissue":
      return statement.status === anchor.status ? null : "status";
    case "activate":
      if (anchor.status !== "declared") {
        return "status";
      }
      return statement.name === anchor.name ? null : "name";
    case "delete":
      return deletePreservationMismatch(anchor, statement);
  }
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
 * after CAS passes — absence is a defect) → the operation's predecessor-match
 * checks → the description acceptance policy → signature verification
 * (predecessor included — prev chaining, rejecting re-statement after delete,
 * transition rules, layout monotonicity).
 *
 * Every check that depends on the predecessor lives here, after the CAS
 * (AUTH_SPEC §12-5's check order): a program runs only predecessor-independent
 * checks before calling it, so a stale-but-honest statement is always a 409
 * and a 422 always means a malformed or forged statement.
 * On success, returns the server-recomputed signed_bytes hash.
 */
export const acceptMetaStatement = Effect.fn("verify-meta.acceptMetaStatement")(function* (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly target: MetaStatementTarget;
  readonly operation: MetaOperation;
  readonly latestMetaVersion: number;
  readonly history: ChainHistoryIndex;
  readonly member: MemberWithDevice;
  readonly statement: MetaStatementInput;
}) {
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
  const mismatched = predecessorMismatch(input.operation, anchor, input.statement);
  if (mismatched !== null) {
    return yield* rejectData({ kind: "payload-mismatch", field: mismatched });
  }
  // The description acceptance policy (§12-8 — v1 statements are out of
  // scope) does **not** apply to deletes: the delete rule is byte-exact
  // preservation of the stored value (checked above), and that value was
  // already checked at acceptance. Applying it would make existing v3
  // variables undeletable after a self-host lowers the limit (a collision
  // with §12-8's "limits never block deletion" principle)
  if (input.operation !== "delete") {
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
