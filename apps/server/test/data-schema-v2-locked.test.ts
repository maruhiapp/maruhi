// Layout v2 — integration tests of the valueless schema's server-side
// acceptance surface — schema-locked (the §12-11 one-time check at
// creation), the description acceptance check (§12-8), and unsupported
// layouts (§12-2 ruling CR). See the top of data-schema-v2.test.ts for
// how the suite is split and support/schema-v2-scenario.ts for the
// shared helpers.

import { describe, expect, it } from "vitest";

import { MAX_SCHEMA_DESCRIPTION_CODEPOINTS } from "../src/policy.ts";
import { encryptValue } from "./support/data-crypto.ts";
import {
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
} from "./support/data-fixture.ts";
import {
  aadFor,
  activateVariableRequest,
  createVariableOk,
  declareVariableOk,
  declareVariableRequest,
  ENV,
  fixture,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  setSchemaPolicyOk,
  token,
  unsignedManifest,
  unsignedPayload,
  v2Fields,
  VAR,
  variableStatementFor,
  varStatements,
} from "./support/data-scenario.ts";
import { createVariableV2Request } from "./support/schema-v2-scenario.ts";

registerDataScenario();

describe("schema-locked (§12-11 — the one-time check at creation)", () => {
  it("locked: v1 creation and v2 creation without varType are 422 schema-required; with varType is accepted", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("locked", OWNER);
    // v1 creation (layoutVersion 1)
    const v1Statement = await variableStatementFor(MEMBER, VAR, "DATABASE_URL");
    const v1Value = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 1 },
      "postgres://alpha",
      { writerUserId: MEMBER, head: fixture.head },
    );
    const v1Bundle = await manifestForStatement(v1Statement, MEMBER);
    const v1Response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: v1Statement,
      value: v1Value,
      manifest: v1Bundle.manifest,
    });
    expect(v1Response.status).toBe(422);
    await expect(v1Response.json()).resolves.toMatchObject({
      _tag: "SchemaPolicyRejected",
      reason: "schema-required",
    });
    // A v2 declaration without varType
    const untyped = await declareVariableRequest({
      variableId: VAR,
      name: "API_KEY",
      actorUserId: MEMBER,
      schema: { varType: "" },
    });
    expect(untyped.status).toBe(422);
    await expect(untyped.json()).resolves.toMatchObject({
      _tag: "SchemaPolicyRejected",
      reason: "schema-required",
    });
    // With varType, both declaration and the value-bundled path are accepted
    await declareVariableOk({ variableId: VAR, name: "API_KEY", schema: { varType: "string" } });
    const typedCreate = await createVariableV2Request({
      variableId: "var-typed",
      name: "TYPED_URL",
      plaintext: "https://example.invalid",
      dek,
      schema: { varType: "url" },
    });
    expect(typedCreate.status).toBe(200);
  });

  it("locked: re-issuing the schema with varType empty is not prevented (a one-time check at creation — not an ongoing invariant)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("locked", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
      schema: { varType: "url" },
    }).then((response) => expect(response.status).toBe(200));
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "" }),
    });
    const { manifest, record } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(204);
    varStatements.set(VAR, { statement, authorUserId: MEMBER });
    record();
  });

  it("locked: activation of a declared created without varType during the enabled period is not retroacted and is accepted", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({ variableId: VAR, name: "API_KEY", schema: { varType: "" } });
    await setSchemaPolicyOk("locked", OWNER);
    const response = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
    });
    expect(response.status).toBe(200);
  });
});

describe("the description acceptance check (§12-8)", () => {
  it("1024 code points are accepted; beyond that is 422 too-long (surrogate pairs count as code points)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    // An astral-plane char (2 UTF-16 units) × 1024 = 1024 code points → accepted
    await declareVariableOk({
      variableId: VAR,
      name: "API_KEY",
      schema: { description: "𠮷".repeat(MAX_SCHEMA_DESCRIPTION_CODEPOINTS) }, // english-exempt: non-BMP codepoint test data
    });
    const rejected = await declareVariableRequest({
      variableId: "var-too-long",
      name: "OTHER_KEY",
      actorUserId: MEMBER,
      schema: { description: "a".repeat(MAX_SCHEMA_DESCRIPTION_CODEPOINTS + 1) },
    });
    expect(rejected.status).toBe(422);
    await expect(rejected.json()).resolves.toMatchObject({
      _tag: "SchemaDescriptionRejected",
      reason: "too-long",
    });
  });

  it("control characters (newlines, ANSI-escape ESC) are 422 control-characters (pinned to a single line)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    for (const description of ["line one\nline two", "colored \u001b[31mred\u001b[0m"]) {
      const response = await declareVariableRequest({
        variableId: VAR,
        name: "API_KEY",
        actorUserId: MEMBER,
        schema: { description },
      });
      expect(response.status).toBe(422);
      await expect(response.json()).resolves.toMatchObject({
        _tag: "SchemaDescriptionRejected",
        reason: "control-characters",
      });
    }
  });
});

/** Build a declaration of an unsupported layout (zero signature, since the signing API cannot produce one). */
function unsupportedLayoutStatement(): Record<string, unknown> {
  return {
    suite: "maruhi/v1",
    environmentId: ENV,
    variableId: VAR,
    name: "API_KEY",
    status: "declared",
    metaVersion: 1,
    prevMetaSigHashHex: "",
    ...v2Fields(),
    layoutVersion: 3,
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

describe("unsupported layouts (§12-2 — ruling CR)", () => {
  it("layoutVersion 3 is a typed 422 unsupported-layout rejection (not crushed into a bad-signature 500)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: unsupportedLayoutStatement(),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
  });

  it("the support-range check precedes schemaPolicy (no misleading error under disabled / locked either)", async () => {
    // The honest answer to a v3 client is always "server update
    // required"; schema-policy-disabled (unchanged by enabling) or
    // schema-required (unchanged by adding varType) must not be returned
    // first (the intent of ruling CR)
    await createEnvironmentOk(fixture, ENV, "App");
    for (const policy of ["disabled", "locked"] as const) {
      await setSchemaPolicyOk(policy, OWNER);
      const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
        statement: unsupportedLayoutStatement(),
        manifest: unsignedManifest(),
      });
      expect(response.status, policy).toBe(422);
      await expect(response.json()).resolves.toMatchObject({
        _tag: "MetaStatementRejected",
        reason: "unsupported-layout",
      });
    }
  });

  it("the support-range check precedes creation's pre-checks (duplicate name) (no duplicate-name for a name-colliding v3)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    // Create an existing variable with the same name as the v3 declaration first, setting up a name collision
    await createVariableOk(dek, "var-existing", "API_KEY", "occupied");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: unsupportedLayoutStatement(),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
  });

  it("the support-range check precedes deletion's just-before match and the meta CAS judgment (the rename / delete paths)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // A v3 successor statement (even in rename form with a stale
    // metaVersion, unsupported-layout settles before the CAS 409)
    const successor = {
      suite: "maruhi/v1",
      environmentId: ENV,
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      metaVersion: 9,
      prevMetaSigHashHex: "ab".repeat(32),
      ...v2Fields(),
      layoutVersion: 3,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
      signatureHex: "00".repeat(64),
    };
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: successor, manifest: unsignedManifest() },
    );
    expect(renamed.status).toBe(422);
    await expect(renamed.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
    // A v3 deletion (unsupported-layout, not the just-before-match payload-mismatch)
    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement: { ...successor, status: "deleted", metaVersion: 2 },
        manifest: unsignedManifest(),
      },
    );
    expect(removed.status).toBe(422);
    await expect(removed.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
    // A v3 activation (unsupported-layout, not the status/name guard or
    // value CAS — the activate path takes the same hoisting as rename /
    // delete)
    const activated = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/activate`,
      token(MEMBER),
      {
        value: unsignedPayload(aadFor(1, 1, { variableId: VAR })),
        statement: successor,
        manifest: unsignedManifest(),
      },
    );
    expect(activated.status).toBe(422);
    await expect(activated.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
  });
});
