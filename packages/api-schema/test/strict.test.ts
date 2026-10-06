// Unit tests of strict acceptance (AUTH_SPEC §12-10 (1)).
//
// Since Effect rc.113, a schema AST's parseOptions is not read by the
// parser. strict is a wrapper around the payload schema, and
// HttpApiBuilder decodes Schema.Union([payload]) with no options. An
// endpoint's HttpApi.ParseOptions is not used (strict-encoding an error
// response becomes HTTP 500).
// The 400 rejection on the acceptance path (a real workerd
// environment) is covered by apps/server/test/strict-payload.test.ts

import { Result, Schema } from "effect";
import { describe, expect, it } from "vitest";

import {
  assertSecurityCriticalPayloadsStrict,
  maruhiApi,
  SECURITY_CRITICAL_PAYLOAD_ENDPOINTS,
  STRICT_EXEMPT_PAYLOAD_ENDPOINTS,
  strictPayload,
} from "../src/index.ts";

const payload = Schema.Struct({ nested: Schema.Struct({ a: Schema.String }) });

/** The shape in which HttpApiBuilder assembles the payload decoder (an options-less Union). */
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
    // Regression protection for the list (including §16-1 head attestation = membership.attest)
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
      // the activation composite (§12-5)
      ["variables", "activate"],
      ["variables", "rename"],
      ["variables", "remove"],
      ["deks", "register"],
      ["auth", "recoveryPut"],
      // master-key wrap ledger (§13-7 — KL3): wraps / segments / re-sealed values = ciphertext of key material
      ["keyWraps", "passkeyRegister"],
      ["keyWraps", "guardianCreate"],
      ["keyWraps", "handoffApprove"],
      // device registry (§13-11 — DK K3): registering public keys = the key-declaration class
      ["devices", "register"],
      ["devices", "requestCreate"],
      ["lease", "issue"],
      ["lease", "propose"],
      ["lease", "preflight"],
      ["rotation", "resolveProposal"],
      ["invites", "issue"],
      ["invites", "accept"],
      // A replication page carries the source's chain, ciphertexts and wraps (§11-7)
      ["mirror", "pages"],
    ]);
  });

  it("classifies every payload-bearing endpoint (no overlap between strict and exempt)", () => {
    // Regression protection for the exempt list: only surfaces outside
    // §12-10 (1) (mutations carrying no signed structure, ciphertext, or
    // key material) may appear
    expect(STRICT_EXEMPT_PAYLOAD_ENDPOINTS).toEqual([
      ["authCli", "cliStart"],
      ["authCli", "cliPoll"],
      ["authCli", "cliApprove"],
      ["deks", "remove"],
      ["rotation", "dismiss"],
      // schemaPolicy's PUT (§12-11 — a 2-value Literal carrying no signed structure)
      ["schemaPolicy", "set"],
      // handoff request (§13-7 — KL3): request_id only
      ["keyWraps", "handoffCreate"],
      // The mirror mark names a source origin only (§11-7)
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
    // An unclassified new endpoint does not silently stay non-strict — it fails at load time
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
    // If an exemption for a removed or renamed surface lingered, it
    // would masquerade as "deliberately exempt" when a security-critical
    // surface later reuses that name, so the exempt side also gets an
    // existence check
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

/**
 * A fake API whose enumerated surfaces are strictPayload (or a plain
 * Struct) and whose exempt surfaces are plain Structs (positive /
 * negative cases of the sweep — both lists' coordinates aligned so the
 * existence check passes).
 */
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
