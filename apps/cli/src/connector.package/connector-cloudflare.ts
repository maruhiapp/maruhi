// The `cloudflare-api-token` connector (the connector overview lives in
// connector.ts): Cloudflare's v4 API tokens. A rotation creates a
// replacement token with the current token's policies; finalize deletes
// the previous token.

import { Effect, Option, Schema } from "effect";
import { HttpBody, HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";

import {
  ConnectorError,
  type ConnectorOutcome,
  type CredentialValues,
  type FinalizeOutcome,
  IssuerEndpoints,
  type RotateInputs,
  transportReason,
  USER_AGENT,
} from "./connector-shared.ts";
import type { RotateRule } from "./rotate-config.ts";

const decoder = new TextDecoder();
const encoder = new TextEncoder();

const CLOUDFLARE_BASE = "https://api.cloudflare.com";

/** Cloudflare's JSON envelope (`{success, errors, result}`; other keys are not read). */
const CloudflareEnvelope = Schema.Struct({
  success: Schema.optionalKey(Schema.Boolean),
  errors: Schema.optionalKey(
    Schema.Array(
      Schema.Struct({
        code: Schema.optionalKey(Schema.Number),
        message: Schema.optionalKey(Schema.String),
      }),
    ),
  ),
  result: Schema.optionalKey(Schema.Unknown),
});
type CloudflareEnvelope = typeof CloudflareEnvelope.Type;

/*
 * The envelope's `result` per step, decoded where it is read. A result that
 * is absent, `null` or another shape decodes to none, and each step answers
 * that with its own wording (an unverifiable token, a definition without a
 * name and policies, a creation without the new value).
 */

/** `/verify`'s result: the id of the token that authenticated. */
const VerifiedToken = Schema.Struct({ id: Schema.NonEmptyString });

/** A token's definition — the fields the replacement copies (the optional ones are checked where they are copied). */
const TokenDefinition = Schema.Struct({
  name: Schema.String,
  policies: Schema.Array(Schema.Unknown),
  condition: Schema.optionalKey(Schema.Unknown),
  expires_on: Schema.optionalKey(Schema.Unknown),
  not_before: Schema.optionalKey(Schema.Unknown),
});

/** The created token: its id and its value (shown only in this answer). */
const CreatedToken = Schema.Struct({ id: Schema.String, value: Schema.NonEmptyString });

function tokensPath(rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>): string {
  return rule.accountId === null
    ? "/client/v4/user/tokens"
    : `/client/v4/accounts/${rule.accountId}/tokens`;
}

const cloudflareCall = Effect.fn("connector-cloudflare.cloudflareCall")(function* (
  bearer: string,
  method: "GET" | "POST" | "DELETE",
  path: string,
  body?: unknown,
): Effect.fn.Return<
  { readonly status: number; readonly envelope: CloudflareEnvelope },
  ConnectorError,
  HttpClient.HttpClient
> {
  const client = yield* HttpClient.HttpClient;
  const endpoints = yield* IssuerEndpoints;
  const base = endpoints.cloudflareBase ?? CLOUDFLARE_BASE;
  let request = HttpClientRequest.make(method)(`${base}${path}`).pipe(
    HttpClientRequest.bearerToken(bearer),
    HttpClientRequest.setHeaders({ "user-agent": USER_AGENT }),
  );
  if (body !== undefined) {
    request = request.pipe(
      HttpClientRequest.setBody(
        HttpBody.raw(JSON.stringify(body), { contentType: "application/json" }),
      ),
    );
  }
  const response = yield* client.execute(request).pipe(
    Effect.mapError(
      (error) =>
        new ConnectorError({
          message: `cloudflare-api-token: ${method} ${path} could not reach Cloudflare (${transportReason(error)})`,
        }),
    ),
  );
  // A successful answer that is not the JSON envelope is a connector
  // error now (it was read as an empty envelope before — silently). An
  // error status may not carry the envelope either, and there the status
  // classification below still owns the message — an edge answer of HTML
  // still reads "Cloudflare answered 502 to …", a 404 still "already".
  const envelope = yield* response.pipe(
    HttpClientResponse.schemaBodyJson(CloudflareEnvelope),
    Effect.catch(() =>
      response.status >= 200 && response.status < 300
        ? Effect.fail(
            new ConnectorError({
              message: `cloudflare-api-token: ${method} ${path} — Cloudflare's answer was not the JSON envelope it returns`,
            }),
          )
        : Effect.succeed<CloudflareEnvelope>({}),
    ),
  );
  return { status: response.status, envelope };
});

function cloudflareFailure(
  what: string,
  status: number,
  envelope: CloudflareEnvelope,
): ConnectorError {
  const first = envelope.errors?.[0];
  const detail =
    first === undefined
      ? ""
      : ` (${first.code ?? "?"}${first.message === undefined ? "" : `: ${first.message}`})`;
  return new ConnectorError({
    message: `cloudflare-api-token: Cloudflare answered ${status} to ${what}${detail}`,
  });
}

/** The id of the token whose value this is (`/verify` with the token itself), or null when it is not valid. */
const cloudflareTokenId = Effect.fn("connector-cloudflare.cloudflareTokenId")(function* (
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  token: string,
): Effect.fn.Return<string | null, ConnectorError, HttpClient.HttpClient> {
  const { status, envelope } = yield* cloudflareCall(token, "GET", `${tokensPath(rule)}/verify`);
  if (status === 401 || status === 403 || envelope.success === false) {
    return null;
  }
  if (status !== 200) {
    return yield* cloudflareFailure("the token verification", status, envelope);
  }
  return Option.match(Schema.decodeUnknownOption(VerifiedToken)(envelope.result), {
    onNone: () => null,
    onSome: (verified) => verified.id,
  });
});

function adminTokenOf(current: CredentialValues, inputs: RotateInputs): string {
  const admin = inputs["token"];
  return decoder.decode(admin ?? current.primary).trim();
}

/** The definition of a token (name, policies, condition, validity window) as the replacement's request body. */
const cloudflareDefinition = Effect.fn("connector-cloudflare.cloudflareDefinition")(function* (
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  admin: string,
  id: string,
): Effect.fn.Return<Record<string, unknown>, ConnectorError, HttpClient.HttpClient> {
  const detail = yield* cloudflareCall(admin, "GET", `${tokensPath(rule)}/${id}`);
  if (detail.status !== 200 || detail.envelope.success === false) {
    return yield* cloudflareFailure(`reading token ${id}`, detail.status, detail.envelope);
  }
  const decoded = Schema.decodeUnknownOption(TokenDefinition)(detail.envelope.result);
  if (Option.isNone(decoded)) {
    return yield* new ConnectorError({
      message: `cloudflare-api-token: token ${id} came back without a name and policies`,
    });
  }
  const definition = decoded.value;
  const request: Record<string, unknown> = {
    name: definition.name,
    policies: definition.policies,
  };
  if (definition.condition !== undefined) {
    request["condition"] = definition.condition;
  }
  if (typeof definition.expires_on === "string") {
    request["expires_on"] = definition.expires_on;
  }
  if (typeof definition.not_before === "string") {
    request["not_before"] = definition.not_before;
  }
  return request;
});

export const rotateCloudflare = Effect.fn("connector-cloudflare.rotateCloudflare")(function* (
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<ConnectorOutcome, ConnectorError, HttpClient.HttpClient> {
  const token = decoder.decode(current.primary).trim();
  const admin = adminTokenOf(current, inputs);
  const id = yield* cloudflareTokenId(rule, token);
  if (id === null) {
    return yield* new ConnectorError({
      message:
        "cloudflare-api-token: the current value is not a valid token (Cloudflare refused to verify it), so its policies cannot be copied. Create the replacement at the issuer and push it",
    });
  }
  const request = yield* cloudflareDefinition(rule, admin, id);
  const created = yield* cloudflareCall(admin, "POST", tokensPath(rule), request);
  if (created.status !== 200 || created.envelope.success === false) {
    return yield* cloudflareFailure(
      "creating the replacement token",
      created.status,
      created.envelope,
    );
  }
  const decoded = Schema.decodeUnknownOption(CreatedToken)(created.envelope.result);
  if (Option.isNone(decoded)) {
    return yield* new ConnectorError({
      message: "cloudflare-api-token: Cloudflare did not return the new token's value",
    });
  }
  const result = decoded.value;
  return {
    values: { primary: encoder.encode(result.value), companions: {} },
    facts: [
      `token ${String(request["name"])}: replacement ${result.id} created with the same policies`,
    ],
    previous: `token ${id} stays valid until you finalize`,
    recovery: `token ${result.id} exists at the issuer and its value is held only by this process (it is not shown) — delete it at the issuer, then re-run the rotation (a re-run creates another token)`,
    warnings: [],
  };
});

export const finalizeCloudflare = Effect.fn("connector-cloudflare.finalizeCloudflare")(function* (
  rule: Extract<RotateRule, { connector: "cloudflare-api-token" }>,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
): Effect.fn.Return<FinalizeOutcome, ConnectorError, HttpClient.HttpClient> {
  const admin = adminTokenOf(current, inputs);
  const previousToken = decoder.decode(previous.primary).trim();
  const currentToken = decoder.decode(current.primary).trim();
  if (previousToken === currentToken) {
    return {
      kind: "nothing" as const,
      facts: ["both versions hold the same token (nothing to delete)"],
    };
  }
  const previousId = yield* cloudflareTokenId(rule, previousToken);
  if (previousId === null) {
    return { kind: "already" as const, facts: ["the previous token is no longer valid"] };
  }
  const currentId = yield* cloudflareTokenId(rule, currentToken);
  if (currentId === previousId) {
    return {
      kind: "nothing" as const,
      facts: [`token ${previousId} is the one in use (nothing to delete)`],
    };
  }
  const deleted = yield* cloudflareCall(admin, "DELETE", `${tokensPath(rule)}/${previousId}`);
  if (deleted.status === 404) {
    return { kind: "already" as const, facts: [`token ${previousId} no longer exists`] };
  }
  if (deleted.status !== 200 || deleted.envelope.success === false) {
    return yield* cloudflareFailure(
      `deleting token ${previousId}`,
      deleted.status,
      deleted.envelope,
    );
  }
  return { kind: "finalized" as const, facts: [`token ${previousId} deleted`] };
});
