import { Effect, Result, Schema, SchemaIssue, SchemaTransformation } from "effect";

import { forEachEndpoint, requireRegisteredEndpoint } from "./sweep.ts";

const STRICT = { onExcessProperty: "error" } as const;

const PROBE_KEY = "__maruhiStrictProbe";

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

export function strictPayload<S extends Schema.Top>(schema: S): S {
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
  ["variables", "activate"],
  ["variables", "rename"],
  ["variables", "remove"],
  ["deks", "register"],
  ["auth", "recoveryPut"],
  ["keyWraps", "passkeyRegister"],
  ["keyWraps", "guardianCreate"],
  ["keyWraps", "handoffApprove"],
  ["devices", "register"],
  ["devices", "requestCreate"],
  ["lease", "issue"],
  ["lease", "propose"],
  ["lease", "preflight"],
  ["rotation", "resolveProposal"],
  ["invites", "issue"],
  ["invites", "accept"],
  ["mirror", "pages"],
];

export const STRICT_EXEMPT_PAYLOAD_ENDPOINTS: ReadonlyArray<
  readonly [group: string, endpoint: string]
> = [
  ["authCli", "cliStart"],
  ["authCli", "cliPoll"],
  ["authCli", "cliApprove"],
  ["deks", "remove"],
  ["rotation", "dismiss"],
  ["schemaPolicy", "set"],
  ["keyWraps", "handoffCreate"],
  ["mirror", "mark"],
];

function assertPayloadRejectsUnknownField(schema: Schema.Top, label: string): void {
  if (!payloadRejectsUnknownField(schema)) {
    throw new Error(
      `strict payload is not parser-effective for ${label}: ` +
        `wrap the payload with strictPayload (AUTH_SPEC §12-10 (1))`,
    );
  }
}

function payloadRejectsUnknownField(schema: Schema.Top): boolean {
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
  for (const [groupName, endpointName] of SECURITY_CRITICAL_PAYLOAD_ENDPOINTS) {
    assertRegisteredPayloadStrict(api, groupName, endpointName);
  }
  for (const [groupName, endpointName] of STRICT_EXEMPT_PAYLOAD_ENDPOINTS) {
    requirePayloadEndpoint(api, groupName, endpointName);
  }
  assertEveryPayloadClassified(api, strict, exempt);
}

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
