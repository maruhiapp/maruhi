import { describe, expect, it } from "vite-plus/test";

import { MAX_SCHEMA_DESCRIPTION_CODEPOINTS } from "../src/policy.ts";
import { encryptValue } from "./support/data-crypto.ts";
import { testEnvironmentId, testProjectId, testVariableId } from "./support/data-crypto.ts";
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
  v3Fields,
  VAR,
  variableStatementFor,
  varStatements,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";
import { createVariableV3Request } from "./support/schema-scenario.ts";

registerDataScenario();

describe("schema-locked (§12-11 — the one-time check at creation)", () => {
  it("locked: v1 creation and v3 creation without varType are 422 schema-required; with varType is accepted", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("locked", OWNER);
    const v1Statement = await variableStatementFor(MEMBER, VAR, "DATABASE_URL");
    const v1Value = await encryptValue(
      dek,
      {
        projectId: testProjectId(projectId),
        environmentId: testEnvironmentId(ENV),
        epoch: 1,
        variableId: testVariableId(VAR),
        version: 1,
      },
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
    await declareVariableOk({ variableId: VAR, name: "API_KEY", schema: { varType: "string" } });
    const typedCreate = await createVariableV3Request({
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
    await createVariableV3Request({
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
      v3: v3Fields({ varType: "" }),
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

function unsupportedLayoutFields(layoutVersion: 2 | 4): Record<string, unknown> {
  const { maxAgeDays, ...v2Shape } = v3Fields();
  return layoutVersion === 2
    ? { ...v2Shape, layoutVersion }
    : { ...v3Fields(), maxAgeDays, layoutVersion };
}

function unsupportedLayoutStatement(layoutVersion: 2 | 4 = 4): Record<string, unknown> {
  return {
    suite: "maruhi/v1",
    environmentId: ENV,
    variableId: VAR,
    name: "API_KEY",
    status: "declared",
    metaVersion: 1,
    prevMetaSigHashHex: "",
    ...unsupportedLayoutFields(layoutVersion),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

describe("unsupported layouts (§12-2 — ruling CR)", () => {
  it("layoutVersion 4 is a typed 422 unsupported-layout rejection (not crushed into a bad-signature 500)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
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

  it("the support-range check precedes schemaPolicy (no misleading error under enabled / locked either)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    for (const policy of ["enabled", "locked"] as const) {
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

  it("the support-range check precedes creation's pre-checks (duplicate name) (no duplicate-name for a name-colliding v4)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
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
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const successor = {
      suite: "maruhi/v1",
      environmentId: ENV,
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      metaVersion: 9,
      prevMetaSigHashHex: "ab".repeat(32),
      ...unsupportedLayoutFields(4),
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

  it("the retired layoutVersion 2 is a typed 422 unsupported-layout on creation (CRYPTO_SPEC §4.2 — 0.15-draft)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: unsupportedLayoutStatement(2),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
  });

  it("a v2 successor on a v3 variable is unsupported-layout, never layout-regression or a stored row (rename / delete)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableV3Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
      schema: { varType: "url" },
    }).then((response) => expect(response.status).toBe(200));
    for (const [status, method] of [
      ["active", "PATCH"],
      ["deleted", "DELETE"],
    ] as const) {
      const signed = await nextVariableStatement({
        variableId: VAR,
        name: "DATABASE_URL",
        status,
        authorUserId: MEMBER,
        v3: v3Fields({ varType: "url" }),
      });
      const { maxAgeDays: _dropped, ...v2Shape } = signed;
      const bundle = await manifestForStatement(signed, MEMBER);
      const response = await requestJson(
        method,
        `/environments/${ENV}/variables/${VAR}`,
        token(MEMBER),
        { statement: { ...v2Shape, layoutVersion: 2 }, manifest: bundle.manifest },
      );
      expect(response.status, status).toBe(422);
      await expect(response.json()).resolves.toMatchObject({
        _tag: "MetaStatementRejected",
        reason: "unsupported-layout",
      });
    }
    const rows = await queryProjectDo(
      projectId,
      "SELECT layout_version, meta_version FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(rows).toEqual([{ layout_version: 3, meta_version: 1 }]);
  });
});
