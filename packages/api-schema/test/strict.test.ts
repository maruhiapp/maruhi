import { Result, Schema } from "effect";
import { describe, expect, it } from "vite-plus/test";

import {
  assertSecurityCriticalPayloadsStrict,
  maruhiApi,
  SECURITY_CRITICAL_PAYLOAD_ENDPOINTS,
  STRICT_EXEMPT_PAYLOAD_ENDPOINTS,
  strictPayload,
} from "../src/index.ts";

const payload = Schema.Struct({ nested: Schema.Struct({ a: Schema.String }) });

const decodeAsBuilder = (schema: Schema.Top, input: unknown) =>
  Schema.decodeUnknownResult(
    Schema.Union([schema]) as unknown as Schema.ConstraintDecoder<unknown>,
  )(input);

describe("strictPayload", () => {
  const strict = strictPayload(payload);

  it("accepts a clean payload through the builder assembly", () => {
    expect(Result.isSuccess(decodeAsBuilder(strict, { nested: { a: "x" } }))).toBe(true);
  });

  it("rejects a root-level unknown field", () => {
    expect(Result.isFailure(decodeAsBuilder(strict, { nested: { a: "x" }, extra: 1 }))).toBe(true);
  });

  it("rejects a nested unknown field", () => {
    expect(Result.isFailure(decodeAsBuilder(strict, { nested: { a: "x", extra: 1 } }))).toBe(true);
  });

  it("rejects an unknown field inside a union member", () => {
    const member = Schema.Struct({ a: Schema.String });
    const union = strictPayload(Schema.Union([member, Schema.Struct({ b: Schema.Number })]));
    expect(Result.isFailure(decodeAsBuilder(union, { a: "x", extra: 1 }))).toBe(true);
  });

  it("rejects an unknown field when encoding", () => {
    const encode = Schema.encodeUnknownResult(strict);
    const extra = encode({ nested: { a: "x" }, extra: 1 });
    const clean = encode({ nested: { a: "x" } });
    expect(Result.isFailure(extra)).toBe(true);
    expect(Result.isSuccess(clean)).toBe(true);
  });

  it("keeps rejecting unknown fields when a check is composed after the wrapper", () => {
    const checked = strictPayload(Schema.Struct({ a: Schema.String })).check(
      Schema.makeFilter(() => undefined),
    );
    expect(Result.isSuccess(decodeAsBuilder(checked, { a: "x" }))).toBe(true);
    expect(Result.isFailure(decodeAsBuilder(checked, { a: "x", extra: 1 }))).toBe(true);
  });

  it("ignores a schema AST parseOptions annotation (Effect rc.113+)", () => {
    const annotated = Schema.Struct({ a: Schema.String }).annotate({
      parseOptions: { onExcessProperty: "error" },
    });
    expect(Result.isSuccess(decodeAsBuilder(annotated, { a: "x", extra: 1 }))).toBe(true);
  });
});

describe("assertSecurityCriticalPayloadsStrict", () => {
  it("passes on the registered maruhi API (also runs at module load)", () => {
    expect(() => assertSecurityCriticalPayloadsStrict(maruhiApi)).not.toThrow();
  });

  it("covers every §12-10 (1) implemented surface", () => {
    expect(SECURITY_CRITICAL_PAYLOAD_ENDPOINTS).toEqual([
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
    ]);
  });

  it("classifies every payload-bearing endpoint (no overlap between strict and exempt)", () => {
    expect(STRICT_EXEMPT_PAYLOAD_ENDPOINTS).toEqual([
      ["authCli", "cliStart"],
      ["authCli", "cliPoll"],
      ["authCli", "cliApprove"],
      ["deks", "remove"],
      ["rotation", "dismiss"],
      ["schemaPolicy", "set"],
      ["keyWraps", "handoffCreate"],
      ["mirror", "mark"],
    ]);
  });

  it("throws when a registered payload is not wrapped", () => {
    const fakeApi = fakeApiFromRegistry(false);
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApi)).toThrow(/not parser-effective/);
  });

  it("accepts a registry whose payloads are wrapped", () => {
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApiFromRegistry(true))).not.toThrow();
  });

  it("throws for a payload-bearing endpoint in neither list (fail-closed)", () => {
    const fakeApi = fakeApiFromRegistry(true);
    const membership = fakeApi.groups["membership"];
    if (membership === undefined) {
      throw new Error("fake api is missing the membership group");
    }
    membership.endpoints["newMutation"] = {
      payload: new Map([
        ["application/json", { schemas: [Schema.Struct({ a: Schema.String })] as [Schema.Top] }],
      ]),
    };
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApi)).toThrow(
      /membership\.newMutation.*not classified/,
    );
  });

  it("throws for a stale exempt entry (endpoint no longer exists)", () => {
    const fakeApi = fakeApiFromRegistry(true);
    const rotation = fakeApi.groups["rotation"];
    if (rotation === undefined) {
      throw new Error("fake api is missing the rotation group");
    }
    delete rotation.endpoints["dismiss"];
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApi)).toThrow(
      /unknown endpoint "rotation\.dismiss"/,
    );
  });

  it("throws when a registered endpoint is missing", () => {
    expect(() => assertSecurityCriticalPayloadsStrict({ groups: {} })).toThrow(/unknown group/);
  });
});

type FakeEndpoint = {
  payload: Map<string, { schemas: [Schema.Top, ...Array<Schema.Top>] }>;
};

type FakeApi = {
  groups: Record<string, { endpoints: Record<string, FakeEndpoint> }>;
};

function fakeApiFromRegistry(strict: boolean): FakeApi {
  const schema = Schema.Struct({ a: Schema.String });
  const entries: readonly (readonly [string, string, boolean])[] = [
    ...SECURITY_CRITICAL_PAYLOAD_ENDPOINTS.map(([g, e]) => [g, e, strict] as const),
    ...STRICT_EXEMPT_PAYLOAD_ENDPOINTS.map(([g, e]) => [g, e, false] as const),
  ];
  const groups: FakeApi["groups"] = {};
  for (const [group, endpoint, isStrict] of entries) {
    groups[group] ??= { endpoints: {} };
    groups[group].endpoints[endpoint] = {
      payload: new Map([
        [
          "application/json",
          { schemas: [isStrict ? strictPayload(schema) : schema] as [Schema.Top] },
        ],
      ]),
    };
  }
  return { groups };
}
