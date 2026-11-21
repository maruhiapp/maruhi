import { type Clock, Data, Effect, Schema } from "effect";
import { Base64Url } from "effect/encoding";
import { HttpClient, HttpClientError, HttpClientRequest, HttpClientResponse } from "effect/http";

import { pemBody, pkcs1ToPkcs8 } from "../der.ts";
import { CLI_VERSION } from "../version.ts";
import type { ConnectorKind } from "./proxy-config.ts";
import type { BrokeredCredential } from "./proxy-rules.ts";

interface Minted {
  readonly value: Uint8Array;
  readonly expiresAt: number | null;
}

export type ConnectorInputs = Readonly<Record<string, Uint8Array>>;

export interface ConnectorDeps {
  readonly client: HttpClient.HttpClient;
  readonly clock: Clock.Clock;
  readonly apiBase?: string | undefined;
}

const REFRESH_MARGIN_MS = 5 * 60 * 1000;

const decoder = new TextDecoder();

class ConnectorError extends Data.TaggedError("ConnectorError")<{
  readonly message: string;
}> {}

function reasonOf(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function transportReason(error: HttpClientError.HttpClientError): string {
  const cause = error.reason.cause;
  return cause instanceof Error ? cause.message : error.message;
}

const GITHUB_API = "https://api.github.com";
const JWT_BACKDATE_S = 60;
const JWT_LIFETIME_S = 9 * 60;

const TokenResponse = Schema.Struct({
  token: Schema.optionalKey(Schema.Unknown),
  expires_at: Schema.optionalKey(Schema.Unknown),
  message: Schema.optionalKey(Schema.Unknown),
});
type TokenResponse = typeof TokenResponse.Type;

function base64Url(bytes: Uint8Array): string {
  return Base64Url.encode(bytes);
}

function importAppKey(pemText: string): Effect.Effect<CryptoKey, ConnectorError> {
  const pkcs1 = pemBody(pemText, "RSA PRIVATE KEY");
  const pkcs8 = pkcs1 === null ? pemBody(pemText, "PRIVATE KEY") : pkcs1ToPkcs8(pkcs1);
  if (pkcs8 === null) {
    return new ConnectorError({
      message:
        "the private key is not a PEM RSA key (expected a `-----BEGIN RSA PRIVATE KEY-----` or `-----BEGIN PRIVATE KEY-----` block, as downloaded from the GitHub App's settings)",
    });
  }
  return Effect.tryPromise({
    try: () =>
      crypto.subtle.importKey(
        "pkcs8",
        pkcs8,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"],
      ),
    catch: () =>
      new ConnectorError({
        message: "the private key could not be imported as an RSA signing key",
      }),
  });
}

function appJwt(
  key: CryptoKey,
  appId: string,
  nowMs: number,
): Effect.Effect<string, ConnectorError> {
  const now = Math.floor(nowMs / 1000);
  const encoder = new TextEncoder();
  const header = base64Url(encoder.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const payload = base64Url(
    encoder.encode(
      JSON.stringify({ iat: now - JWT_BACKDATE_S, exp: now + JWT_LIFETIME_S, iss: appId }),
    ),
  );
  const signingInput = `${header}.${payload}`;
  return Effect.map(
    Effect.tryPromise({
      try: () => crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, encoder.encode(signingInput)),
      catch: (error) => new ConnectorError({ message: reasonOf(error, "unknown failure") }),
    }),
    (signature) => `${signingInput}.${base64Url(new Uint8Array(signature))}`,
  );
}

function textInput(inputs: ConnectorInputs, name: string): Effect.Effect<string, ConnectorError> {
  const bytes = inputs[name];
  if (bytes === undefined) {
    return new ConnectorError({ message: `input ${name} is missing` });
  }
  const text = decoder.decode(bytes).trim();
  if (!/^[\x21-\x7E]{1,128}$/.test(text)) {
    return new ConnectorError({ message: `input ${name} is not a single-line identifier` });
  }
  return Effect.succeed(text);
}

function parseTokenResponse(
  status: number,
  record: TokenResponse,
): Effect.Effect<Minted, ConnectorError> {
  if (status !== 201) {
    return new ConnectorError({
      message: `GitHub answered ${status} (${typeof record.message === "string" ? record.message : "no message"})`,
    });
  }
  const token = record.token;
  if (typeof token !== "string" || token.length === 0) {
    return new ConnectorError({ message: "GitHub's response carried no token" });
  }
  const expiresAt =
    typeof record.expires_at === "string" ? Date.parse(record.expires_at) : Number.NaN;
  return Effect.succeed({
    value: new TextEncoder().encode(token),
    expiresAt: Number.isFinite(expiresAt) ? expiresAt : null,
  });
}

const mintGithubApp = Effect.fn("proxy-connector.mintGithubApp")(function* (
  inputs: ConnectorInputs,
  deps: ConnectorDeps,
): Effect.fn.Return<Minted, ConnectorError, HttpClient.HttpClient> {
  const appId = yield* textInput(inputs, "appId");
  const installationId = yield* textInput(inputs, "installationId");
  if (!/^\d+$/.test(installationId)) {
    return yield* new ConnectorError({
      message: "input installationId must be the numeric installation ID",
    });
  }
  const keyBytes = inputs["privateKey"];
  if (keyBytes === undefined) {
    return yield* new ConnectorError({ message: "input privateKey is missing" });
  }
  const key = yield* importAppKey(decoder.decode(keyBytes));
  const jwt = yield* appJwt(key, appId, deps.clock.currentTimeMillisUnsafe());
  const base = deps.apiBase ?? GITHUB_API;
  const client = yield* HttpClient.HttpClient;
  const response = yield* client
    .execute(
      HttpClientRequest.post(`${base}/app/installations/${installationId}/access_tokens`).pipe(
        HttpClientRequest.setHeaders({
          authorization: `Bearer ${jwt}`,
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
          "user-agent": `maruhi-cli/${CLI_VERSION}`,
        }),
      ),
    )
    .pipe(Effect.mapError((error) => new ConnectorError({ message: transportReason(error) })));
  const record = yield* response.pipe(HttpClientResponse.schemaBodyJson(TokenResponse)).pipe(
    Effect.catchReason("HttpClientError", "DecodeError", () => Effect.succeed<TokenResponse>({})),
    Effect.catchTag(
      "SchemaError",
      () => Effect.succeed<TokenResponse>({}),
      (error) => Effect.fail(new ConnectorError({ message: transportReason(error) })),
    ),
  );
  return yield* parseTokenResponse(response.status, record);
});

const revokeGithubApp = Effect.fn("proxy-connector.revokeGithubApp")(function* (
  token: Uint8Array,
  deps: ConnectorDeps,
): Effect.fn.Return<void, ConnectorError, HttpClient.HttpClient> {
  const base = deps.apiBase ?? GITHUB_API;
  const client = yield* HttpClient.HttpClient;
  const response = yield* client
    .execute(
      HttpClientRequest.delete(`${base}/installation/token`).pipe(
        HttpClientRequest.setHeaders({
          authorization: `token ${decoder.decode(token)}`,
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
          "user-agent": `maruhi-cli/${CLI_VERSION}`,
        }),
      ),
    )
    .pipe(Effect.mapError((error) => new ConnectorError({ message: transportReason(error) })));
  if (response.status !== 204 && response.status !== 401) {
    return yield* new ConnectorError({
      message: `GitHub answered ${response.status} to the revocation`,
    });
  }
});

interface ConnectorImpl {
  readonly mint: (
    inputs: ConnectorInputs,
    deps: ConnectorDeps,
  ) => Effect.Effect<Minted, ConnectorError, HttpClient.HttpClient>;
  readonly revoke: (
    value: Uint8Array,
    deps: ConnectorDeps,
  ) => Effect.Effect<void, ConnectorError, HttpClient.HttpClient>;
}

const CONNECTORS: Readonly<Record<ConnectorKind, ConnectorImpl>> = {
  "github-app": { mint: mintGithubApp, revoke: revokeGithubApp },
};

function runConnector<A>(input: {
  readonly effect: Effect.Effect<A, ConnectorError, HttpClient.HttpClient>;
  readonly deps: ConnectorDeps;
}): Promise<A> {
  return Effect.runPromise(
    input.effect.pipe(Effect.provideService(HttpClient.HttpClient, input.deps.client)),
  );
}

export function makeConnectorCredential(input: {
  readonly name: string;
  readonly kind: ConnectorKind;
  readonly inputs: ConnectorInputs;
  readonly placeholder: string;
  readonly hosts: BrokeredCredential["hosts"];
  readonly surfaces: BrokeredCredential["surfaces"];
  readonly deps: ConnectorDeps;
}): BrokeredCredential {
  const { mint, revoke } = CONNECTORS[input.kind];
  let cached: Minted | null = null;
  let previous: Minted | null = null;
  let inFlight: Promise<Uint8Array> | null = null;
  const fresh = (now: number): boolean =>
    cached !== null && (cached.expiresAt === null || cached.expiresAt - REFRESH_MARGIN_MS > now);
  return {
    name: input.name,
    placeholder: input.placeholder,
    hosts: input.hosts,
    surfaces: input.surfaces,
    known: () =>
      [cached, previous]
        .filter((minted): minted is Minted => minted !== null)
        .map((minted) => minted.value),
    release: async () => {
      const held = [cached, previous].filter((minted): minted is Minted => minted !== null);
      cached = null;
      previous = null;
      const failures: string[] = [];
      for (const minted of held) {
        await runConnector({ effect: revoke(minted.value, input.deps), deps: input.deps }).catch(
          (error: unknown) => {
            failures.push(error instanceof Error ? error.message : "revocation failed");
          },
        );
      }
      if (failures.length > 0) {
        throw new Error(failures.join("; "));
      }
    },
    resolve: () => {
      if (cached !== null && fresh(input.deps.clock.currentTimeMillisUnsafe())) {
        return Promise.resolve(cached.value);
      }
      if (inFlight === null) {
        inFlight = runConnector({ effect: mint(input.inputs, input.deps), deps: input.deps })
          .then((minted) => {
            previous = cached;
            cached = minted;
            return minted.value;
          })
          .catch((error: unknown) => {
            const reason = error instanceof Error ? error.message : "unknown failure";
            throw new Error(`connector ${input.kind} for ${input.name}: ${reason}`);
          })
          .finally(() => {
            inFlight = null;
          });
      }
      return inFlight;
    },
  };
}
