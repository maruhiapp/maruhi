import { LeaseUnauthorizedError, LeaseUnavailableError } from "@maruhi/api-schema";
import { Context, Effect, Exit, Result } from "effect";
import { Digest, Signature } from "effect/crypto";
import { Base64Url } from "effect/encoding";
import { Jws } from "effect/jose";

import { type JwksCacheShape, makeJwksCache } from "./jwks.ts";

type AllowedAlg = "RS256" | "ES256";

const SUPPORTED_ISSUERS: readonly string[] = ["https://token.actions.githubusercontent.com"];

const ALLOWED_ALGS: readonly AllowedAlg[] = ["RS256", "ES256"];

export const OIDC_CLOCK_SKEW_MS = 60 * 1000;
const CLOCK_SKEW_MS = OIDC_CLOCK_SKEW_MS;

export interface VerifiedOidcToken {
  readonly issuer: string;
  readonly subject: string;
  readonly audiences: readonly string[];
  readonly claims: Readonly<Record<string, unknown>>;
  readonly expiresAtSec: number;
  readonly signingInputHashHex: string;
}

export interface OidcVerifierShape {
  readonly verify: (
    token: string,
    nowMs: number,
  ) => Effect.Effect<
    VerifiedOidcToken,
    LeaseUnauthorizedError | LeaseUnavailableError,
    Digest.Digest | Signature.Signature
  >;
}

export class OidcVerifier extends Context.Service<OidcVerifier, OidcVerifierShape>()(
  "OidcVerifier",
) {}

const unauthorized = (reason: LeaseUnauthorizedError["reason"]) =>
  Effect.fail(new LeaseUnauthorizedError({ reason }));

function asRecord(value: unknown): Readonly<Record<string, unknown>> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringClaim(claims: Readonly<Record<string, unknown>>, name: string): string | null {
  const value = claims[name];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function numericClaim(claims: Readonly<Record<string, unknown>>, name: string): number | null {
  const value = claims[name];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function audiencesOf(claims: Readonly<Record<string, unknown>>): readonly string[] | null {
  const value = claims["aud"];
  if (typeof value === "string") {
    return value.length > 0 ? [value] : null;
  }
  if (Array.isArray(value) && value.length > 0 && value.every((a) => typeof a === "string")) {
    return value as readonly string[];
  }
  return null;
}

interface ParsedToken {
  readonly alg: AllowedAlg;
  readonly kid: string | null;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly signature: Uint8Array;
  readonly signingInput: Uint8Array;
}

interface DecodedSegments {
  readonly header: Readonly<Record<string, unknown>>;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly signature: Uint8Array;
  readonly signingInput: Uint8Array;
}

const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]*$/;

function decodeBase64Url(segment: string): Uint8Array | null {
  if (!BASE64URL_SEGMENT.test(segment) || segment.length % 4 === 1) {
    return null;
  }
  const decoded = Base64Url.decode(segment);
  return Result.isSuccess(decoded) ? decoded.success : null;
}

function decodeSegmentJson(segment: string): unknown {
  const bytes = decodeBase64Url(segment);
  if (bytes === null) {
    return null;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return null;
  }
}

function decodeSegments(token: string): DecodedSegments | null {
  const segments = token.split(".");
  if (segments.length !== 3) {
    return null;
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments;
  if (
    headerSegment === undefined ||
    payloadSegment === undefined ||
    signatureSegment === undefined
  ) {
    return null;
  }
  const header = asRecord(decodeSegmentJson(headerSegment));
  const claims = asRecord(decodeSegmentJson(payloadSegment));
  const signature = decodeBase64Url(signatureSegment);
  if (header === null || claims === null || signature === null) {
    return null;
  }
  return {
    header,
    claims,
    signature,
    signingInput: new TextEncoder().encode(`${headerSegment}.${payloadSegment}`),
  };
}

function parseToken(token: string): Effect.Effect<ParsedToken, LeaseUnauthorizedError> {
  const decoded = decodeSegments(token);
  if (decoded === null) {
    return unauthorized("malformed-token");
  }
  if (decoded.header["crit"] !== undefined) {
    return unauthorized("unsupported-crit");
  }
  const alg = decoded.header["alg"];
  if (typeof alg !== "string" || !ALLOWED_ALGS.includes(alg as AllowedAlg)) {
    return unauthorized("unsupported-alg");
  }
  const kid = decoded.header["kid"];
  return Effect.succeed({
    alg: alg as AllowedAlg,
    kid: typeof kid === "string" ? kid : null,
    claims: decoded.claims,
    signature: decoded.signature,
    signingInput: decoded.signingInput,
  });
}

function checkTimes(
  claims: Readonly<Record<string, unknown>>,
  nowMs: number,
): Effect.Effect<void, LeaseUnauthorizedError> {
  const exp = numericClaim(claims, "exp");
  const iat = numericClaim(claims, "iat");
  if (exp === null || iat === null) {
    return unauthorized("missing-claim");
  }
  if (exp * 1000 + CLOCK_SKEW_MS <= nowMs) {
    return unauthorized("token-expired");
  }
  if (iat * 1000 - CLOCK_SKEW_MS > nowMs) {
    return unauthorized("token-not-yet-valid");
  }
  const nbf = numericClaim(claims, "nbf");
  if (nbf !== null && nbf * 1000 - CLOCK_SKEW_MS > nowMs) {
    return unauthorized("token-not-yet-valid");
  }
  return Effect.void;
}

export function makeOidcVerifier(
  jwks: JwksCacheShape = makeJwksCache(),
  supportedIssuers: readonly string[] = SUPPORTED_ISSUERS,
): OidcVerifierShape {
  return {
    verify: Effect.fn("verifier.verify")(function* (token, nowMs) {
      const parsed = yield* parseToken(token);
      const issuer = stringClaim(parsed.claims, "iss");
      if (issuer === null) {
        return yield* unauthorized("missing-claim");
      }
      if (!supportedIssuers.includes(issuer)) {
        return yield* unauthorized("unsupported-issuer");
      }
      const resolved = yield* jwks
        .resolveKey(issuer, parsed.kid)
        .pipe(
          Effect.mapError(() => new LeaseUnavailableError({ reason: "oidc-jwks-unavailable" })),
        );
      if (resolved === null) {
        return yield* unauthorized("unknown-key");
      }
      if (parsed.alg !== resolved.key.algorithm) {
        return yield* unauthorized("unsupported-alg");
      }
      const canonicalToken = `${token.slice(0, token.lastIndexOf("."))}.${Base64Url.encode(parsed.signature)}`;
      const verification = yield* Effect.exit(Jws.verify(canonicalToken, resolved.key));
      if (!Exit.isSuccess(verification)) {
        return yield* unauthorized("signature-invalid");
      }
      yield* checkTimes(parsed.claims, nowMs);
      const subject = stringClaim(parsed.claims, "sub");
      const audiences = audiencesOf(parsed.claims);
      const expiresAtSec = numericClaim(parsed.claims, "exp");
      if (subject === null || audiences === null || expiresAtSec === null) {
        return yield* unauthorized("missing-claim");
      }
      const signingInputHashHex = yield* Effect.orDie(
        Effect.flatMap(Digest.Digest, (digest) =>
          digest.digestHex(Digest.sha256, parsed.signingInput),
        ),
      );
      return {
        issuer,
        subject,
        audiences,
        claims: parsed.claims,
        expiresAtSec,
        signingInputHashHex,
      };
    }),
  };
}
