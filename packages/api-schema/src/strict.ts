// strict-ifying security-critical acceptance (AUTH_SPEC §12-10 (1)).
//
// Since Effect v4 rc.113, the schema AST annotation `parseOptions` is not
// read by the parser (SchemaAST.ParseOptions's description: options
// apply to the whole parse; a schema annotation does not override them).
// The pre-rc.113 `strictPayload` = a schema annotation silently drops
// unknown fields when the caller decodes with no options.
//
// Instead the payload schema is wrapped in a wrapper. decode and encode
// pass `{ onExcessProperty: "error" }` to the inner schema, so unknown
// fields are rejected including through nesting and unions.
// HttpApiBuilder decodes the payload as `Schema.Union([schema])` with no
// options. The wrapper rejects inside that assembly too.
//
// `HttpApi.ParseOptions` is not used. The same options would also flow
// to success / error encoding and to path params / headers.
// `Schema.TaggedError` carries stack-derived non-enumerable fields
// (`originalLine`, etc.), so strict-encoding an error response becomes
// an HttpApiSchemaError and falls to HTTP 500. Because the header codec
// sees all incoming headers, an API-wide `onExcessProperty: "error"` is
// not used either.
//
// Shared schemas themselves are not wrapped. strict must not propagate
// into other endpoints' responses that return the same schema. This
// endpoint's success / error encoding keeps dropping unknown fields as
// before.
//
// The load-time sweep looks at no annotation: it hands an unknown field
// to an options-less decode and requires an `UnexpectedKey` (adding
// `.check()` afterward keeps the rejection; only an AST `parseOptions`
// annotation does not reject). Effectiveness (an actual 400) is
// guaranteed by the fixed acceptance-path test
// (apps/server/test/strict-payload.test.ts).

import { Effect, Result, Schema, SchemaIssue, SchemaTransformation } from "effect";

import { forEachEndpoint, requireRegisteredEndpoint } from "./sweep.ts";

/** The strict options passed to the inner schema's decode / encode. */
const STRICT = { onExcessProperty: "error" } as const;

/**
 * The probe key the sweep treats as an "unknown field". Same name as
 * the fixed acceptance-path test (`__maruhiStrictProbe`).
 */
const PROBE_KEY = "__maruhiStrictProbe";

/**
 * The structural slice of an `HttpApi` the sweep walks (the concrete
 * `HttpApi<...>` type is invariant in its group union, so the nominal
 * `HttpApi.Top` is not usable as a parameter type here).
 */
interface SweepableApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: {
          readonly payload: ReadonlyMap<
            string,
            { readonly schemas: readonly [Schema.Top, ...Array<Schema.Top>] }
          >;
        };
      };
    };
  };
}

/**
 * Wraps a security-critical payload schema so unknown fields are rejected
 * with a schema error (HTTP 400) instead of being silently dropped
 * (AUTH_SPEC §12-10 (1)).
 *
 * Decode and encode both pass `{ onExcessProperty: "error" }` to `schema`,
 * including nested structs and unions. The wrapper is what the server decodes
 * (no parse options) and what the client encodes. Do not put
 * `HttpApi.ParseOptions` on the endpoint: the same options apply to success
 * and error codecs, and encoding a `Schema.TaggedError` under strict excess
 * checking fails closed into HTTP 500.
 *
 * Shared component schemas stay unwrapped. Other endpoints that reuse the same
 * schema without this wrapper keep the default (strip unknown fields). Checks
 * composed after the wrapper do not turn the rejection off.
 */
export function strictPayload<S extends Schema.Top>(schema: S): S {
  // If `to` were `Schema.toType(schema)`, unknown keys would be dropped
  // from the encode input first and strict encode would succeed. With
  // Unknown on both sides, encode sees the extra keys. The type stays
  // the inner schema's (handlers and clients use `Type` for the payload
  // type).
  return Schema.Unknown.pipe(
    Schema.decodeTo(
      Schema.Unknown,
      SchemaTransformation.transformEffect({
        decode: (input: unknown) =>
          Schema.decodeUnknownEffect(
            schema,
            STRICT,
          )(input).pipe(Effect.mapError((error) => error.issue)),
        encode: (value: unknown) =>
          Schema.encodeUnknownEffect(
            schema,
            STRICT,
          )(value).pipe(Effect.mapError((error) => error.issue)),
      }),
    ),
  ) as unknown as S;
}

/**
 * The security-critical mutation payload roots of the maruhi HTTP API — the
 * §12-10 (1) enumeration projected onto implemented endpoints, as
 * `[group, endpoint]` pairs:
 *
 * - chain appends incl. genesis (§11-4): membership init / append
 * - environment creation / rotation composites (§12-4)
 * - value pushes and meta operations (§12-5)
 * - DEK wrap registration (§12-6)
 * - recovery blob registration (§13-2)
 * - lease claims (§14)
 * - invitation issue / accept (§15-2)
 * - head-attestation submission (§16-1): membership attest
 */
export const SECURITY_CRITICAL_PAYLOAD_ENDPOINTS: ReadonlyArray<
  readonly [group: string, endpoint: string]
> = [
  ["membership", "init"],
  ["membership", "append"],
  ["membership", "attest"],
  ["environments", "create"],
  ["environments", "rotate"],
  ["environments", "rename"],
  ["environments", "remove"],
  ["variables", "create"],
  ["variables", "push"],
  // the activation composite (§12-5 — belongs to §12-10 (1)'s "value push / meta operations" class)
  ["variables", "activate"],
  ["variables", "rename"],
  ["variables", "remove"],
  ["deks", "register"],
  ["auth", "recoveryPut"],
  // master-key wrap ledger (§13-7 — KL3): wraps / segments / re-sealed values = ciphertext of key material
  ["keyWraps", "passkeyRegister"],
  ["keyWraps", "guardianCreate"],
  ["keyWraps", "handoffApprove"],
  // device registry (§13-11 — DK K3): registering public keys = the key-declaration class (never silently drop unknown fields)
  ["devices", "register"],
  ["devices", "requestCreate"],
  ["lease", "issue"],
  ["invites", "issue"],
  ["invites", "accept"],
];

/**
 * Payload-bearing endpoints that are deliberately **not** strict: mutations
 * that carry no signed structure, ciphertext or key material, so they fall
 * outside the §12-10 (1) enumeration. Every payload-bearing endpoint of the
 * API must appear in exactly one of the two lists — the sweep fails closed on
 * an endpoint that is in neither, so adding a payload endpoint forces a
 * conscious strict / non-strict decision instead of silently defaulting to
 * the permissive schema behavior.
 */
export const STRICT_EXEMPT_PAYLOAD_ENDPOINTS: ReadonlyArray<
  readonly [group: string, endpoint: string]
> = [
  // CLI login (AUTH_SPEC §4 — the pre-auth handoff surface; carries no
  // signed structure, ciphertext, or key material): start = issuance
  // parameters only, poll = the flow credential only, approve = the
  // browser's raw form POST (the handler uniformly refuses missing /
  // mismatched values)
  ["authCli", "cliStart"],
  ["authCli", "cliPoll"],
  ["authCli", "cliApprove"],
  // only coordinate references to the wrap to delete (the §12-6 repair path)
  ["deks", "remove"],
  // only an enumeration of (environment, variable) identifiers (AUDIT_SPEC §7)
  ["rotation", "dismiss"],
  // schemaPolicy configuration (AUTH_SPEC §12-11 — carries no signed
  // structure; the 3-value Literal closes Schema validation)
  ["schemaPolicy", "set"],
  // handoff request (§13-7 — KL3): only request_id (the SHA-256 of the
  // ephemeral public key). Carries no signed structure, ciphertext, or
  // key material
  ["keyWraps", "handoffCreate"],
];

/**
 * Asserts that decoding `schema` with no parse options rejects an unknown
 * field (AUTH_SPEC §12-10 (1)). Throws on failure.
 *
 * The assembly matches `HttpApiBuilder`: `Schema.Union([schema])` and no
 * options. An AST `parseOptions` annotation does not satisfy this check.
 */
function assertPayloadRejectsUnknownField(schema: Schema.Top, label: string): void {
  if (!payloadRejectsUnknownField(schema)) {
    throw new Error(
      `strict payload is not parser-effective for ${label}: ` +
        `wrap the payload with strictPayload (AUTH_SPEC §12-10 (1))`,
    );
  }
}

/** Whether an options-less decode rejects an unknown field with `UnexpectedKey`. */
function payloadRejectsUnknownField(schema: Schema.Top): boolean {
  // Schema.Top's DecodingServices is unknown. Security-critical payloads
  // require no services, so the same Union as the builder is treated as
  // a closed decoder.
  const decoded = Schema.decodeUnknownResult(
    Schema.Union([schema]) as unknown as Schema.ConstraintDecoder<unknown>,
  )({
    [PROBE_KEY]: true,
  });
  return Result.isFailure(decoded) && hasUnexpectedKey(decoded.failure.issue);
}

function hasUnexpectedKey(issue: SchemaIssue.Issue): boolean {
  // Reading `_tag` directly is forbidden by oxlint's no-underscore-dangle.
  if (issue instanceof SchemaIssue.UnexpectedKey) {
    return true;
  }
  if ("issue" in issue && SchemaIssue.isIssue(issue.issue) && hasUnexpectedKey(issue.issue)) {
    return true;
  }
  if ("issues" in issue && Array.isArray(issue.issues)) {
    return issue.issues.some((child) => SchemaIssue.isIssue(child) && hasUnexpectedKey(child));
  }
  return false;
}

/**
 * Load-time sweep (AUTH_SPEC §12-10 (1)): asserts that every registered
 * security-critical payload rejects an unknown field when decoded with no
 * parse options, and that every payload-bearing endpoint of the API is
 * classified in exactly one of `SECURITY_CRITICAL_PAYLOAD_ENDPOINTS` /
 * `STRICT_EXEMPT_PAYLOAD_ENDPOINTS`. An endpoint in neither list throws, so
 * for **body payloads** the §12-10 (1) rule "classify new and revised
 * endpoints against this standard" is machine-enforced instead of remaining a
 * process obligation. The sweep decodes the payload schema the way
 * `HttpApiBuilder` does (a union, no parse options). An unknown field arriving
 * via `query` or `headers` on an endpoint that does not declare those schemas
 * is outside its view (today that blind spot holds the `audit` reads and
 * `auth.githubCallback`, a state-changing GET). A future mutation modelling
 * request data as `query` or `headers` must be classified by review — and
 * must not receive `HttpApi.ParseOptions`, because header codecs see every
 * incoming header and the same options strict-encode error responses into
 * HTTP 500.
 */
export function assertSecurityCriticalPayloadsStrict(api: SweepableApi): void {
  const strict = new Set(SECURITY_CRITICAL_PAYLOAD_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
  const exempt = new Set(STRICT_EXEMPT_PAYLOAD_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
  for (const key of strict) {
    if (exempt.has(key)) {
      throw new Error(
        `security-critical payload sweep: "${key}" is listed as both strict and exempt`,
      );
    }
  }
  // 1. Listed surfaces exist + reject unknown fields (catches renames and missing wrappers)
  for (const [groupName, endpointName] of SECURITY_CRITICAL_PAYLOAD_ENDPOINTS) {
    assertRegisteredPayloadStrict(api, groupName, endpointName);
  }
  // 2. Exempt surfaces exist (purge stale entries — if an exemption for
  //     a removed or renamed surface lingered, a later security-critical
  //     surface reusing that name would masquerade as "deliberately
  //     exempt", so the same existence check as the strict side applies)
  for (const [groupName, endpointName] of STRICT_EXEMPT_PAYLOAD_ENDPOINTS) {
    requirePayloadEndpoint(api, groupName, endpointName);
  }
  assertEveryPayloadClassified(api, strict, exempt);
}

/** One listed surface: existence check + unknown-field rejection (sweep item 1). */
function assertRegisteredPayloadStrict(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): void {
  const endpoint = requirePayloadEndpoint(api, groupName, endpointName);
  const label = `${groupName}.${endpointName}`;
  for (const content of endpoint.payload.values()) {
    for (const schema of content.schemas) {
      assertPayloadRejectsUnknownField(schema, label);
    }
  }
}

/**
 * The reverse-direction fail-closed check (sweep item 3): every
 * endpoint carrying a payload is classified into one of the two lists —
 * an unclassified new surface does not silently stay non-strict; it
 * fails here.
 */
function assertEveryPayloadClassified(
  api: SweepableApi,
  strict: ReadonlySet<string>,
  exempt: ReadonlySet<string>,
): void {
  forEachEndpoint(api, (key, endpoint) => {
    if (endpoint.payload.size > 0 && !strict.has(key) && !exempt.has(key)) {
      throw new Error(
        `security-critical payload sweep: "${key}" carries a payload but is not classified — ` +
          `add it to SECURITY_CRITICAL_PAYLOAD_ENDPOINTS (AUTH_SPEC §12-10 (1)) or, if it ` +
          `carries no signed structure, ciphertext or key material, to ` +
          `STRICT_EXEMPT_PAYLOAD_ENDPOINTS`,
      );
    }
  });
}

/** Existence check for one list entry: requires the group, the endpoint, and a payload. */
function requirePayloadEndpoint(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): SweepableApi["groups"][string]["endpoints"][string] {
  const endpoint = requireRegisteredEndpoint(
    api,
    "security-critical payload sweep",
    groupName,
    endpointName,
  );
  if (endpoint.payload.size === 0) {
    throw new Error(
      `security-critical payload sweep: "${groupName}.${endpointName}" has no payload schema`,
    );
  }
  return endpoint;
}
