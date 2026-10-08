// Layout v3 (the schema layout) — integration tests of the valueless
// schema's server-side acceptance surface — schema-locked (the §12-11
// one-time check at creation), the description acceptance check
// (§12-8), and unsupported layouts (§12-2 ruling CR — the retired
// layout 2 included). See the top of data-schema.test.ts for how the
// suite is split and support/schema-scenario.ts for the shared helpers.

import { describe, expect, it } from "vitest";

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
    // v1 creation (layoutVersion 1)
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
    // A v3 declaration without varType
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
    // Declared under the default enabled
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

/**
 * The schema-field carriage of an unsupported layout: 4 (the first future
 * layout) keeps the v3 field set; the retired 2 carries the v3 set without
 * maxAgeDays (the former v2 wire shape).
 */
function unsupportedLayoutFields(layoutVersion: 2 | 4): Record<string, unknown> {
  const { maxAgeDays, ...v2Shape } = v3Fields();
  return layoutVersion === 2
    ? { ...v2Shape, layoutVersion }
    : { ...v3Fields(), maxAgeDays, layoutVersion };
}

/** Build a declaration of an unsupported layout (zero signature, since the signing API cannot produce one). */
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
    // The honest answer to a v4 client is always "server update
    // required"; schema-required (unchanged by adding varType) must not
    // be returned first (the intent of ruling CR)
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
    // Create an existing variable with the same name as the v4 declaration first, setting up a name collision
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
    // A v4 successor statement (even in rename form with a stale
    // metaVersion, unsupported-layout settles before the CAS 409)
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
    // A v4 deletion (unsupported-layout, not the just-before-match payload-mismatch)
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
    // A v4 activation (unsupported-layout, not the status/name guard or
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
    // The successor is signed as a valid v3 statement and then relabelled
    // to the retired layout (the signing API cannot produce layout 2): the
    // support-range check settles before the signature, the CAS, and the
    // monotonicity check
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
    // Nothing was stored: the variable is still at metaVersion 1 on layout 3
    const rows = await queryProjectDo(
      projectId,
      "SELECT layout_version, meta_version FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(rows).toEqual([{ layout_version: 3, meta_version: 1 }]);
  });
});
