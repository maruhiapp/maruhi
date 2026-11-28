import { maruhiApi } from "@maruhi/api-schema";
import { Cause, Exit, Predicate, Schema } from "effect";
import type { HttpApiEndpoint, HttpApiGroup, HttpApiMiddleware } from "effect/http-api";
import { HttpApi, HttpApiSchema } from "effect/http-api";

type ApiGroups = typeof maruhiApi extends HttpApi.HttpApi<infer _Id, infer Groups> ? Groups : never;

type NameOfGroup<Group> = Group extends HttpApiGroup.Constraint
  ? `${Group["identifier"]}.${HttpApiEndpoint.Identifier<HttpApiGroup.Endpoints<Group>>}`
  : never;

export type ApiEndpointName = NameOfGroup<ApiGroups>;

type EndpointNamed<Name extends string> = Name extends `${infer Group}.${infer Endpoint}`
  ? HttpApiEndpoint.WithIdentifier<HttpApiGroup.EndpointsWithIdentifier<ApiGroups, Group>, Endpoint>
  : never;

type EncodedOf<S> = S extends { readonly schema: { readonly Encoded: infer Encoded } }
  ? Encoded
  : never;

export type ApiSuccess<Name extends ApiEndpointName> = EncodedOf<EndpointNamed<Name>["~Success"]>;

export type ApiError<Name extends ApiEndpointName> =
  | EncodedOf<EndpointNamed<Name>["~Error"]>
  | HttpApiMiddleware.ErrorSchema<EndpointNamed<Name>["~Middleware"]>["Encoded"];

export type ApiPayload<Name extends ApiEndpointName> = EncodedOf<EndpointNamed<Name>["~Payload"]>;

export type ApiParams<Name extends ApiEndpointName> = EncodedOf<EndpointNamed<Name>["~Params"]>;

export type ApiReply<Name extends ApiEndpointName> =
  | { readonly status: number; readonly json: Exclude<ApiSuccess<Name>, void> | ApiError<Name> }
  | (void extends ApiSuccess<Name>
      ? { readonly status: number; readonly json?: undefined }
      : never);

export interface ApiRoute<Name extends ApiEndpointName> {
  readonly name: Name;
  readonly method: string;
  readonly path: string;
  readonly match: (method: string, pathname: string) => ApiParams<Name> | null;
  readonly verdictOf: (status: number, json: unknown) => ReplyVerdict;
}

export type ReplyVerdict =
  | { readonly accepted: true; readonly contentType: string | undefined }
  | { readonly accepted: false; readonly refusal: string };

type BodyCheck = (json: unknown) => ReplyVerdict;

interface DeclaredRoute {
  readonly method: string;
  readonly path: string;
  readonly bodies: ReadonlyMap<number, readonly BodyCheck[]>;
}

function wireOf(json: unknown): unknown {
  return json === undefined ? undefined : JSON.parse(JSON.stringify(json));
}

function bodyCheckOf(schema: Schema.Top): BodyCheck {
  if (HttpApiSchema.isNoContent(schema.ast)) {
    return (json) =>
      json === undefined
        ? { accepted: true, contentType: undefined }
        : { accepted: false, refusal: "it has no body" };
  }
  const encoding = HttpApiSchema.getResponseEncodingSchema(schema);
  if (!Predicate.isTagged(encoding, "Json")) {
    return () => ({ accepted: false, refusal: `its body is ${encoding.contentType}, not JSON` });
  }
  const codec = Schema.toCodecJson(schema) as unknown as Schema.ConstraintDecoder<unknown>;
  const decode = Schema.decodeUnknownExit(codec, { onExcessProperty: "error" });
  return (json) => {
    const exit = decode(wireOf(json));
    return Exit.isSuccess(exit)
      ? { accepted: true, contentType: encoding.contentType }
      : { accepted: false, refusal: Cause.pretty(exit.cause) };
  };
}

function declaredRoutes(): ReadonlyMap<string, DeclaredRoute> {
  const routes = new Map<string, DeclaredRoute>();
  HttpApi.reflect(maruhiApi, {
    onGroup: () => undefined,
    onEndpoint: ({ group, endpoint, successes, errors }) => {
      routes.set(`${group.identifier}.${endpoint.identifier}`, {
        method: endpoint.method,
        path: endpoint.path,
        bodies: new Map(
          [...successes, ...errors].map(([status, schemas]) => [status, schemas.map(bodyCheckOf)]),
        ),
      });
    },
  });
  return routes;
}

const ROUTES = declaredRoutes();

function matchPath(pattern: string, pathname: string): Record<string, string> | null {
  const expected = pattern.split("/");
  const actual = pathname.split("/");
  if (expected.length !== actual.length) {
    return null;
  }
  const params: Record<string, string> = {};
  for (const [index, segment] of expected.entries()) {
    const value = actual[index] ?? "";
    if (segment.startsWith(":")) {
      if (value === "") {
        return null;
      }
      params[segment.slice(1)] = decodeURIComponent(value);
    } else if (segment !== value) {
      return null;
    }
  }
  return params;
}

export function apiRoute<const Name extends ApiEndpointName>(name: Name): ApiRoute<Name> {
  const declared = ROUTES.get(name);
  if (declared === undefined) {
    throw new Error(`no api endpoint named ${name}`);
  }
  return {
    name,
    method: declared.method,
    path: declared.path,
    match: (method, pathname) =>
      method === declared.method
        ? (matchPath(declared.path, pathname) as ApiParams<Name> | null)
        : null,
    verdictOf: (status, json) => {
      const checks = declared.bodies.get(status);
      if (checks === undefined) {
        return { accepted: false, refusal: `${name} declares no response with status ${status}` };
      }
      const refusals: string[] = [];
      for (const check of checks) {
        const verdict = check(json);
        if (verdict.accepted) {
          return verdict;
        }
        refusals.push(verdict.refusal);
      }
      return {
        accepted: false,
        refusal: `${name} declares no such body for status ${status}: ${refusals.join(" / ")}`,
      };
    },
  };
}
