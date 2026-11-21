import { encodeHex } from "./bytes.ts";
import type { EnvironmentId, ProjectId, UserId, VariableId } from "./chain-types.ts";
import { encodeLengthPrefixed, type LengthPrefixedField } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

export type MetaStatementStatus = "active" | "deleted" | "declared";

export type MetaVarType = "" | "string" | "number" | "boolean" | "url";

const META_VAR_TYPES: readonly string[] = ["", "string", "number", "boolean", "url"];

export interface MetaVariableSchema {
  readonly varType: MetaVarType;
  readonly required: "true" | "false";
  readonly description: string;
  readonly maxAgeDays: string;
}

export const MAX_META_MAX_AGE_DAYS = 3650;

const MAX_AGE_DAYS_FORM = /^(?:[1-9][0-9]{0,3})?$/;

export function isMetaMaxAgeDays(text: string): boolean {
  return MAX_AGE_DAYS_FORM.test(text) && (text === "" || Number(text) <= MAX_META_MAX_AGE_DAYS);
}

export const SUPPORTED_META_LAYOUT_VERSIONS: readonly number[] = [1, 3];

export function metaLayoutVersionOf(carrier: {
  readonly layoutVersion?: number | undefined;
}): number {
  return carrier.layoutVersion ?? 1;
}

export type MetaStatementTarget =
  | { readonly kind: "variable"; readonly variableId: VariableId }
  | { readonly kind: "environment" };

export interface MetaStatementContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly target: MetaStatementTarget;
  readonly name: string;
  readonly status: MetaStatementStatus;
  readonly layoutVersion?: number | undefined;
  readonly schema?: MetaVariableSchema | undefined;
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly authorUserId: UserId;
  readonly chainHeadHashHex: string;
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

type MetaLayout =
  | { readonly version: 1 }
  | {
      readonly version: 3;
      readonly variableId: VariableId;
      readonly schema: MetaVariableSchema;
    };

function selectMetaLayout(context: MetaStatementContext): CryptoResult<MetaLayout> {
  if (
    context.layoutVersion !== undefined &&
    (!Number.isSafeInteger(context.layoutVersion) || context.layoutVersion < 1)
  ) {
    return invalidInput("context layoutVersion");
  }
  const version = metaLayoutVersionOf(context);
  if (SUPPORTED_META_LAYOUT_VERSIONS.includes(version)) {
    if (version === 1) {
      return layoutV1Of(context);
    }
    if (version === 3) {
      return layoutV3Of(context);
    }
  }
  return { ok: false, error: { kind: "UnsupportedMetaLayout", layoutVersion: version } };
}

function layoutV1Of(context: MetaStatementContext): CryptoResult<MetaLayout> {
  return context.schema === undefined
    ? { ok: true, value: { version: 1 } }
    : invalidInput("context schema");
}

function layoutV3Of(context: MetaStatementContext): CryptoResult<MetaLayout> {
  if (context.target.kind !== "variable") {
    return invalidInput("context layoutVersion");
  }
  return context.schema === undefined
    ? invalidInput("context schema")
    : {
        ok: true,
        value: { version: 3, variableId: context.target.variableId, schema: context.schema },
      };
}

function layoutV1FieldInvalid(context: MetaStatementContext): string | null {
  const statuses: readonly string[] =
    context.target.kind === "environment" ? ["active"] : ["active", "deleted"];
  return statuses.includes(context.status) ? null : "context status";
}

function layoutV3FieldInvalid(
  context: MetaStatementContext,
  schema: MetaVariableSchema,
): string | null {
  if (!META_VAR_TYPES.includes(schema.varType)) {
    return "context varType";
  }
  if (schema.required !== "true" && schema.required !== "false") {
    return "context required";
  }
  const maxAge: unknown = schema.maxAgeDays;
  if (typeof maxAge !== "string" || !isMetaMaxAgeDays(maxAge)) {
    return "context maxAgeDays";
  }
  const statuses: readonly string[] = ["active", "deleted", "declared"];
  return statuses.includes(context.status) ? null : "context status";
}

function contextInvalidField(context: MetaStatementContext, layout: MetaLayout): string | null {
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
  const fields =
    layout.version === 1
      ? layoutV1FieldInvalid(context)
      : layoutV3FieldInvalid(context, layout.schema);
  if (fields !== null) {
    return fields;
  }
  if (context.authorUserId.length === 0) {
    return "context authorUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

function checkedMetaLayout(context: MetaStatementContext): CryptoResult<MetaLayout> {
  const selected = selectMetaLayout(context);
  if (!selected.ok) {
    return selected;
  }
  const field = contextInvalidField(context, selected.value);
  return field === null ? selected : invalidInput(field);
}

export function metaContextRejection(context: MetaStatementContext): CryptoError | null {
  const checked = checkedMetaLayout(context);
  return checked.ok ? null : checked.error;
}

function encodeMetaSignedBytes(context: MetaStatementContext, layout: MetaLayout): Uint8Array {
  switch (layout.version) {
    case 3: {
      const maxAge: unknown = layout.schema.maxAgeDays;
      return encodeLengthPrefixed([
        `${context.suite}/var-meta-sig-v3`,
        context.projectId,
        context.environmentId,
        layout.variableId,
        context.name,
        context.status,
        layout.schema.varType,
        layout.schema.required,
        layout.schema.description,
        typeof maxAge === "string" ? maxAge : "",
        context.metaVersion,
        context.prevMetaSigHashHex,
        context.authorUserId,
        context.chainHeadHashHex,
        context.chainHeadSeq,
      ]);
    }
    case 1: {
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
  }
}

export function buildMetaSignedBytes(context: MetaStatementContext): CryptoResult<Uint8Array> {
  const selected = selectMetaLayout(context);
  return selected.ok
    ? { ok: true, value: encodeMetaSignedBytes(context, selected.value) }
    : selected;
}

export async function computeMetaSignedBytesHash(
  context: MetaStatementContext,
): Promise<CryptoResult<string>> {
  const layout = checkedMetaLayout(context);
  if (!layout.ok) {
    return layout;
  }
  return {
    ok: true,
    value: encodeHex(await sha256(encodeMetaSignedBytes(context, layout.value))),
  };
}

export async function signMetaStatement(input: {
  readonly context: MetaStatementContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const layout = checkedMetaLayout(input.context);
  if (!layout.ok) {
    return layout;
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
        encodeMetaSignedBytes(input.context, layout.value) as BufferSource,
      ),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

export async function verifyMetaStatementSignature(input: {
  readonly context: MetaStatementContext;
  readonly signatureHex: string;
  readonly authorPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const layout = checkedMetaLayout(input.context);
  if (!layout.ok) {
    return layout;
  }
  return verifyEd25519Over(
    encodeMetaSignedBytes(input.context, layout.value),
    input.signatureHex,
    input.authorPublicKey,
    {
      kind: "MetaStatementInvalid",
      reason: "signature-invalid",
    },
  );
}
