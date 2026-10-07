// CRYPTO_SPEC §4.2: signed statements of variable / environment metadata
// (Ed25519).
// var_meta_signed_bytes = LP("<suite>/var-meta-sig", project_id, environment_id,
//                            variable_id, name, status, meta_version,
//                            prev_meta_sig_hash_hex, author_user_id,
//                            chain_head_hash_hex, chain_head_seq)
// env_meta_signed_bytes = LP("<suite>/env-meta-sig", project_id, environment_id,
//                            name, status, meta_version, prev_meta_sig_hash_hex,
//                            author_user_id, chain_head_hash_hex, chain_head_seq)
// Layout v3 (the schema layout — 0.8-draft session 46 rulings CR / CS for
// the schema fields and declared, PF6 R9 for max_age_days; variables only —
// environment meta stays v1):
// var_meta_signed_bytes_v3 = LP("<suite>/var-meta-sig-v3", project_id,
//                               environment_id, variable_id, name, status,
//                               var_type, required, description,
//                               max_age_days, meta_version,
//                               prev_meta_sig_hash_hex, author_user_id,
//                               chain_head_hash_hex, chain_head_seq)
// The supported layouts are {1, 3}: layout v2 (the v3 sequence without
// max_age_days under "<suite>/var-meta-sig-v2") was retired in 0.15-draft
// and is refused like any other unsupported layout.
// The suite and the var / env kind / layout version are bound by the domain
// string (same shape as §4.1 / §5.1. The layout version is local to the
// statement kind and the suite stays put — maruhi/v2 is reserved for a PQ
// hybrid). The wire's layoutVersion (omitted = 1) selects which layout's
// signed_bytes is computed, and the support-range check happens **before
// signature verification**, rejecting overage as the typed error
// UnsupportedMetaLayout (an honest failure mode that does not collapse
// into signature-invalid — ruling CR).
// Numbers (meta_version / chain_head_seq) are base-10 stringified per §2.1,
// and binaries (hashes) go onto the LP as lowercase hex strings.
// name / description are bound as raw UTF-8 byte strings (byte-exact — NFC
// normalization is the pre-signing client's duty; verifiers do not
// normalize. §4.2).
// Test vectors: test-vectors/metadata-signature.json
//
// The signature's semantics: "author_user_id, knowing the state at chain
// position (chain_head_hash, chain_head_seq), bound this name / status to
// this stable identifier" — attribution, content authenticity, and
// authorization-time binding (§4.2). A meta statement carries no
// epoch-equivalent freshness anchor (injection with a forward meta_version
// is a known residue undetected in v1 — §14.3-5). Verification of the
// declared head, authorization time, and prev chaining is carried by
// meta-verify.ts (history queries by chain-history.ts); this module holds
// only the low-level normalization, signing, and hashing.

import { encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed, type LengthPrefixedField } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

/**
 * Lifecycle status a metadata statement binds (CRYPTO_SPEC §4.2).
 * `declared` — declared but no value set — exists only in variable layout v3
 * (ruling CS: v1 is unchanged); layout 1 statements are limited to the first two.
 */
export type MetaStatementStatus = "active" | "deleted" | "declared";

/**
 * Declared type of a variable's value (CRYPTO_SPEC §4.2 layout v3). A closed
 * set — `""` means unspecified; no validation DSL / enum / defaults (ruling CT).
 * The declaration is advisory (§14.3-7): the signature proves the author
 * declared this type, never that values conform to it.
 */
export type MetaVarType = "" | "string" | "number" | "boolean" | "url";

const META_VAR_TYPES: readonly string[] = ["", "string", "number", "boolean", "url"];

/**
 * Schema fields of a variable meta statement in layout v3 (CRYPTO_SPEC §4.2):
 * bound byte-exactly into the signed bytes between `status` and
 * `meta_version`. `required` is mandatory-explicit (`"true" | "false"` — the
 * empty string is rejected so no client-side default interpretation can
 * diverge); `description` is free UTF-8 (byte-exact, verifiers never
 * normalize — display-side neutralization is AUTH_SPEC §12-8's duty).
 */
export interface MetaVariableSchema {
  readonly varType: MetaVarType;
  readonly required: "true" | "false";
  readonly description: string;
  /**
   * PF6 R9 "expiring values" (CRYPTO_SPEC §4.2): the number of days after a
   * value's push within which it should be replaced, as the signed decimal
   * string (`"1"`…`"3650"`, no leading zeros), or `""` = no declaration.
   * Mandatory (fail-closed like `required`). The declaration is advisory
   * like the type (§14.3-7): the signature proves the author declared the
   * interval, never that a value was replaced in time.
   */
  readonly maxAgeDays: string;
}

/** The largest declarable max age (days). Ten years; a longer interval is "no interval". */
export const MAX_META_MAX_AGE_DAYS = 3650;

// The signed form of max_age_days: empty, or a decimal without leading
// zeros within the bound (one value = one byte string — signature
// uniqueness)
const MAX_AGE_DAYS_FORM = /^(?:[1-9][0-9]{0,3})?$/;

/** Whether `text` is a well-formed signed max_age_days ("" or 1..3650 without leading zeros). */
export function isMetaMaxAgeDays(text: string): boolean {
  return MAX_AGE_DAYS_FORM.test(text) && (text === "" || Number(text) <= MAX_META_MAX_AGE_DAYS);
}

/**
 * Supported wire layout versions of variable meta statements (§4.2): v1 and
 * the schema layout v3. Layout 2 is retired (0.15-draft) and refused as
 * unsupported like v4+.
 */
export const SUPPORTED_META_LAYOUT_VERSIONS: readonly number[] = [1, 3];

/**
 * Resolves the effective layout version of a statement or predecessor
 * (CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2): the wire `layoutVersion` field is a
 * carrier field outside the signed bytes, and omission means layout 1.
 */
export function metaLayoutVersionOf(carrier: {
  readonly layoutVersion?: number | undefined;
}): number {
  return carrier.layoutVersion ?? 1;
}

/**
 * The stable identifier a statement binds the name/status to: a variable
 * (var-meta-sig) or the environment itself (env-meta-sig). The two kinds use
 * distinct domain strings, so signatures never transplant across kinds.
 */
export type MetaStatementTarget =
  | { readonly kind: "variable"; readonly variableId: string }
  | { readonly kind: "environment" };

/**
 * Fields bound by a metadata-statement signature (CRYPTO_SPEC §4.2): the full
 * wire form of one statement version plus its authorization anchor. The name
 * is bound byte-exactly as UTF-8; hashes are lowercase hex strings.
 */
export interface MetaStatementContext {
  readonly suite: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly target: MetaStatementTarget;
  readonly name: string;
  readonly status: MetaStatementStatus;
  /**
   * Wire layout version (§4.2 — omitted = 1). Selects which layout's signed
   * bytes are computed. Layout 3 is variable statements only and requires
   * `schema`; environment statements stay layout 1 (outside the schema
   * layout).
   */
  readonly layoutVersion?: number | undefined;
  /** Layout v3 schema fields — present iff the layout version is 3. */
  readonly schema?: MetaVariableSchema | undefined;
  /** 1-based counter (creation = 1; each rename / delete increments). */
  readonly metaVersion: number;
  /**
   * SHA-256 (lowercase hex) of the previous statement's signed bytes; the
   * empty string for metaVersion 1 (the §4.2 chaining convention — same as §4.1).
   */
  readonly prevMetaSigHashHex: string;
  /** The author's own internal user id (binds attribution to the identity). */
  readonly authorUserId: string;
  /** Entry hash of the chain head the author last verified (§6.1). */
  readonly chainHeadHashHex: string;
  /** Seq of that head (both hash and seq are signed; mismatch fails). */
  readonly chainHeadSeq: number;
}

function numericFieldInvalid(context: MetaStatementContext): string | null {
  if (!Number.isSafeInteger(context.metaVersion) || context.metaVersion < 1) {
    return "context metaVersion";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

// Binary values are lowercase hex only (the same discipline as the §4.1
// implementation — allowing uppercase hex would give one value multiple
// normalized forms and break signature uniqueness)
function hexFieldInvalid(context: MetaStatementContext): string | null {
  if (
    context.prevMetaSigHashHex !== "" &&
    !isLowercaseHexOfLength(context.prevMetaSigHashHex, SHA256_HEX_LENGTH)
  ) {
    return "context prevMetaSigHashHex";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  return null;
}

// suite and the signed coordinates (projectId / environmentId) must be
// non-empty. The non-empty checks of the coordinates are for defensive
// consistency (LP makes even empty values unambiguous = not a
// vulnerability, but the check level is kept uniform across fields). No
// legitimate call signs empty coordinates
function coordinateFieldInvalid(context: MetaStatementContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.environmentId.length === 0) {
    return "context environmentId";
  }
  return null;
}

// Layout-1 structure check: no schema fields exist and status is 2-valued
// for a variable (declared is v3-only — ruling CS: v1 declared is
// InvalidInput as a wire-shape structure violation. Vector
// v1-declared-status) and active-only for the environment itself
// (2026-10-07 — an environment's deletion is the chain op
// delete_environment, §6.2, so no environment statement records one.
// Vector env-status-deleted)
function layoutV1FieldInvalid(context: MetaStatementContext): string | null {
  if (context.schema !== undefined) {
    return "context schema";
  }
  const statuses: readonly string[] =
    context.target.kind === "environment" ? ["active"] : ["active", "deleted"];
  return statuses.includes(context.status) ? null : "context status";
}

// Layout-3 structure check: variable statements only (environment meta
// stays v1 — §4.2), schema fields mandatory, var_type a closed set,
// required mandatory-explicit and the empty string not allowed
// (fail-closed — vector v3-empty-required), max_age_days mandatory and
// well-formed ("" or 1..3650 — vectors v3-missing-max-age /
// v3-max-age-leading-zero / v3-max-age-out-of-range), status 3-valued
function layoutV3FieldInvalid(context: MetaStatementContext): string | null {
  if (context.target.kind !== "variable") {
    return "context layoutVersion";
  }
  if (context.schema === undefined) {
    return "context schema";
  }
  if (!META_VAR_TYPES.includes(context.schema.varType)) {
    return "context varType";
  }
  if (context.schema.required !== "true" && context.schema.required !== "false") {
    return "context required";
  }
  // The wire-derived context may lack the field despite the type
  // (fail-closed — the v3-missing-max-age vector)
  const maxAge: unknown = context.schema.maxAgeDays;
  if (typeof maxAge !== "string" || !isMetaMaxAgeDays(maxAge)) {
    return "context maxAgeDays";
  }
  const statuses: readonly string[] = ["active", "deleted", "declared"];
  return statuses.includes(context.status) ? null : "context status";
}

// Layout-dependent structure check (precondition: the layout version is
// within the supported range {1, 3}). The status vocabulary and the
// presence of schema fields are decided by the layout
function layoutFieldInvalid(context: MetaStatementContext): string | null {
  return metaLayoutVersionOf(context) === 1
    ? layoutV1FieldInvalid(context)
    : layoutV3FieldInvalid(context);
}

// Structure validation of the signing target. The metaVersion ↔ prev
// coupling (1 = empty / > 1 = 64-hex) is not checked here: the verify side
// must be able to verify the signature of a "valid signature but
// rule-violating" statement first (the vectors' rule negatives such as
// v1-nonempty-prev), and the coupling is rejected with a reason code as a
// verification rule (meta-verify.ts's prev-shape-mismatch) — the same
// asymmetry as value-sign.ts.
function contextInvalidField(context: MetaStatementContext): string | null {
  const coordinate = coordinateFieldInvalid(context);
  if (coordinate !== null) {
    return coordinate;
  }
  if (context.target.kind === "variable" && context.target.variableId.length === 0) {
    return "context variableId";
  }
  if (context.name.length === 0) {
    return "context name";
  }
  const layout = layoutFieldInvalid(context);
  if (layout !== null) {
    return layout;
  }
  if (context.authorUserId.length === 0) {
    return "context authorUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

/**
 * Validates a metadata-statement context (shared by sign / verify / hash).
 * The check order is fixed by CRYPTO_SPEC §4.2 (ruling CR): the layoutVersion
 * support range is inspected **before** any layout-dependent field validation
 * and before signature verification, so an unsupported layout surfaces as the
 * typed `UnsupportedMetaLayout` ("client update required") — never as an
 * `InvalidInput` about fields the verifier cannot understand, and never as a
 * signature failure indistinguishable from tampering.
 */
export function metaContextRejection(context: MetaStatementContext): CryptoError | null {
  if (
    context.layoutVersion !== undefined &&
    (!Number.isSafeInteger(context.layoutVersion) || context.layoutVersion < 1)
  ) {
    return { kind: "InvalidInput", field: "context layoutVersion" };
  }
  const layout = metaLayoutVersionOf(context);
  if (!SUPPORTED_META_LAYOUT_VERSIONS.includes(layout)) {
    return { kind: "UnsupportedMetaLayout", layoutVersion: layout };
  }
  const field = contextInvalidField(context);
  return field === null ? null : { kind: "InvalidInput", field };
}

/**
 * Builds the canonical byte string signed for one metadata statement
 * (CRYPTO_SPEC §4.2). The domain string embeds the suite identifier, the
 * statement kind (var / env) and — for variable layout v3 — the layout
 * version, so a signature never transplants across suites, kinds or layouts
 * (layout confusion fails structurally as a signature mismatch — §1
 * principle 6). Callers must
 * validate the context first (sign / verify / hash below do); this builder
 * assumes valid input.
 */
export function buildMetaSignedBytes(context: MetaStatementContext): Uint8Array {
  if (
    metaLayoutVersionOf(context) === 3 &&
    context.target.kind === "variable" &&
    context.schema !== undefined
  ) {
    // The schema fields right after status, under the layout's own domain
    // string (a v3 signature never verifies under v1 and vice versa — §1
    // principle 6). The encoder is total: a context missing max_age_days
    // encodes it as the empty declaration (validation rejects it first)
    const maxAge: unknown = context.schema.maxAgeDays;
    return encodeLengthPrefixed([
      `${context.suite}/var-meta-sig-v3`,
      context.projectId,
      context.environmentId,
      context.target.variableId,
      context.name,
      context.status,
      context.schema.varType,
      context.schema.required,
      context.schema.description,
      typeof maxAge === "string" ? maxAge : "",
      context.metaVersion,
      context.prevMetaSigHashHex,
      context.authorUserId,
      context.chainHeadHashHex,
      context.chainHeadSeq,
    ]);
  }
  const fields: LengthPrefixedField[] = [
    context.target.kind === "variable"
      ? `${context.suite}/var-meta-sig`
      : `${context.suite}/env-meta-sig`,
    context.projectId,
    context.environmentId,
  ];
  if (context.target.kind === "variable") {
    fields.push(context.target.variableId);
  }
  fields.push(
    context.name,
    context.status,
    context.metaVersion,
    context.prevMetaSigHashHex,
    context.authorUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  );
  return encodeLengthPrefixed(fields);
}

/**
 * SHA-256 (lowercase hex) of the canonical signed bytes — the value carried
 * as the next statement's `prev_meta_sig_hash_hex` (the §4.2 chaining) and compared
 * for fork evidence (two valid signatures over distinct signed bytes at the
 * same metaVersion — §14.2-5).
 */
export async function computeMetaSignedBytesHash(
  context: MetaStatementContext,
): Promise<CryptoResult<string>> {
  const rejection = metaContextRejection(context);
  if (rejection !== null) {
    return { ok: false, error: rejection };
  }
  return { ok: true, value: encodeHex(await sha256(buildMetaSignedBytes(context))) };
}

/**
 * Signs one metadata statement with the author's chain signing key (Ed25519,
 * CRYPTO_SPEC §4.2). Returns the signature as lowercase hex — the wire form
 * of `VariableMetaStatement.signatureHex` (AUTH_SPEC §12-2).
 *
 * Signing enforces the metaVersion ↔ prev coupling (metaVersion 1 signs an
 * empty prev, later versions sign a 64-hex prev) and that a creation
 * (metaVersion 1) is never `deleted` (deletion is an increment — §4.2; a
 * creation is active or, for v3 variables, declared — a value-less
 * declaration). Producing a
 * rule-violating statement is always a caller bug, unlike verification where
 * such wire data must be rejected with a typed reason instead.
 */
export async function signMetaStatement(input: {
  readonly context: MetaStatementContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const rejection = metaContextRejection(input.context);
  if (rejection !== null) {
    return { ok: false, error: rejection };
  }
  if ((input.context.metaVersion === 1) !== (input.context.prevMetaSigHashHex === "")) {
    return invalidInput("context prevMetaSigHashHex");
  }
  if (input.context.metaVersion === 1 && input.context.status === "deleted") {
    return invalidInput("context status");
  }
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        input.signingKey,
        buildMetaSignedBytes(input.context) as BufferSource,
      ),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

/**
 * Verifies one metadata-statement signature against an author's Ed25519
 * public key (CRYPTO_SPEC §4.2). This is the raw signature check only — head
 * existence, head-time authorization / role level and prev chaining are the
 * history-based checks in `verifyDistributedMetaStatement` (meta-verify.ts).
 */
export async function verifyMetaStatementSignature(input: {
  readonly context: MetaStatementContext;
  readonly signatureHex: string;
  readonly authorPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const rejection = metaContextRejection(input.context);
  if (rejection !== null) {
    return { ok: false, error: rejection };
  }
  return verifyEd25519Over(
    buildMetaSignedBytes(input.context),
    input.signatureHex,
    input.authorPublicKey,
    {
      kind: "MetaStatementInvalid",
      reason: "signature-invalid",
    },
  );
}
