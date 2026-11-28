import { encryptValue, testEnvironmentId, testProjectId, testVariableId } from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import { MAX_SCHEMA_DESCRIPTION_CODEPOINTS } from "../src/policy.ts";
import { identityOf, vectorKeyOf } from "./support/data-crypto.ts";
import {
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  declareVariableOk,
  declareVariableRequest,
  deleteVariableRequest,
  ENV,
  fixture,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  setSchemaPolicyOk,
  token,
  v3Fields,
  VAR,
  variableStatementV3For,
  varStatements,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";
import { createVariableV3Request } from "./support/schema-scenario.ts";

registerDataScenario();

async function reissueAuditRows(
  event: "var.renamed" | "var.schema_reissued",
): Promise<readonly Record<string, unknown>[]> {
  return queryProjectDo(
    projectId,
    "SELECT variable_id, actor_key_fingerprint, payload FROM audit_events WHERE event = ?",
    event,
  );
}

describe("transitions and layout monotonicity (§12-5)", () => {
  it("active → declared (rename form) is 422 payload-mismatch (the acceptance check of an unchanged status)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableV3Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    }).then((response) => expect(response.status).toBe(200));
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "declared",
      authorUserId: MEMBER,
      v3: v3Fields(),
    });
    const { manifest } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "status",
    });
  });

  it("declared → declared schema re-issuance and rename are 204 (updatable while still a declaration)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "API_TOKEN",
      status: "declared",
      authorUserId: MEMBER,
      v3: v3Fields({ varType: "string", required: false, description: "renamed declaration" }),
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

  it("a v1 successor (rename) on a v3 variable is 422 layout-regression (layout monotonicity)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableV3Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    }).then((response) => expect(response.status).toBe(200));
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
    });
    const { manifest } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "layout-regression",
    });
  });

  it("declared re-creation with a deleted ID is 409 retired (no ID reuse — §12-1)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await deleteVariableRequest(VAR, MEMBER)).status).toBe(204);
    const response = await declareVariableRequest({
      variableId: VAR,
      name: "API_KEY",
      actorUserId: MEMBER,
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "VariableConflict",
      reason: "retired",
    });
  });
});

async function seedV3Variable(dek: Uint8Array): Promise<void> {
  await setSchemaPolicyOk("enabled", OWNER);
  const response = await createVariableV3Request({
    variableId: VAR,
    name: "DATABASE_URL",
    plaintext: "postgres://alpha",
    dek,
    schema: { varType: "url", required: true, description: "primary database" },
  });
  expect(response.status).toBe(200);
}

describe("the just-before match of a delete statement's schema field and layout (§12-5)", () => {
  it("a v3 deletion preserving the schema field and layout is 204 (declared deletions share the shape)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV3Variable(dek);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v3: v3Fields({ varType: "url", required: true, description: "primary database" }),
    });
    const { manifest, record } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(204);
    record();
    await declareVariableOk({ variableId: "var-declared-del", name: "PENDING_KEY" });
    const declared = varStatements.get("var-declared-del");
    expect(declared).toBeDefined();
    const declaredDelete = await nextVariableStatement({
      variableId: "var-declared-del",
      name: "PENDING_KEY",
      status: "deleted",
      authorUserId: MEMBER,
      v3: v3Fields(),
    });
    const bundled = await manifestForStatement(declaredDelete, MEMBER);
    const declaredResponse = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/var-declared-del`,
      token(MEMBER),
      { statement: declaredDelete, manifest: bundled.manifest },
    );
    expect(declaredResponse.status).toBe(204);
  });

  it("a deletion that alters the schema field is 422 payload-mismatch (not accepted even with a valid signature — tampered-deletion blocking)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV3Variable(dek);
    const cases: readonly (readonly [Partial<Parameters<typeof v3Fields>[0]>, string])[] = [
      [{ varType: "string", required: true, description: "primary database" }, "varType"],
      [{ varType: "url", required: false, description: "primary database" }, "required"],
      [{ varType: "url", required: true, description: "totally different" }, "description"],
    ];
    for (const [schema, field] of cases) {
      const statement = await nextVariableStatement({
        variableId: VAR,
        name: "DATABASE_URL",
        status: "deleted",
        authorUserId: MEMBER,
        v3: v3Fields(schema),
      });
      const { manifest } = await manifestForStatement(statement, MEMBER);
      const response = await requestJson(
        "DELETE",
        `/environments/${ENV}/variables/${VAR}`,
        token(MEMBER),
        { statement, manifest },
      );
      expect(response.status, field).toBe(422);
      await expect(response.json()).resolves.toMatchObject({ _tag: "PayloadMismatch", field });
    }
  });

  it("a deletion's description is outside the acceptance policy (an alteration is a just-before-match 422 — it does not fall to an out-of-contract 500)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV3Variable(dek);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v3: v3Fields({
        varType: "url",
        required: true,
        description: "a".repeat(MAX_SCHEMA_DESCRIPTION_CODEPOINTS + 1),
      }),
    });
    const { manifest } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "description",
    });
  });

  it("a v1-shaped deletion on a v3 variable is 422 payload-mismatch (layoutVersion — the layout is also just-before-matched)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV3Variable(dek);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
    });
    const { manifest } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "layoutVersion",
    });
  });
});

describe("schema re-issuance and reversibility (§12-5 / §12-11)", () => {
  it("a schema-field-only change on a v3 variable is accepted under the same rules as a rename and reflected in distribution", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableV3Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
      schema: { varType: "string", required: true, description: "" },
    }).then((response) => expect(response.status).toBe(200));
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v3: v3Fields({ varType: "url", required: false, description: "connection string" }),
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
    const metadata = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    const body = (await metadata.json()) as { variables: readonly Record<string, unknown>[] };
    expect(body.variables[0]).toMatchObject({
      varType: "url",
      required: false,
      description: "connection string",
      metaVersion: 2,
    });
    expect(await reissueAuditRows("var.renamed")).toHaveLength(0);
    const reissued = await reissueAuditRows("var.schema_reissued");
    expect(reissued).toHaveLength(1);
    expect(reissued[0]).toMatchObject({
      variable_id: VAR,
      actor_key_fingerprint: vectorKeyOf(MEMBER).key_fingerprint_hex,
    });
    const payload = JSON.parse(String(reissued[0]?.["payload"])) as Record<string, unknown>;
    expect(payload).toMatchObject({ name: "DATABASE_URL" });
    expect(payload).not.toHaveProperty("varType");
    expect(payload).not.toHaveProperty("description");
  });

  it("a re-issuance changing both name and schema field is a single var.renamed row (the rename is the primary event — one operation, one row)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableV3Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
      schema: { varType: "string", required: true, description: "" },
    }).then((response) => expect(response.status).toBe(200));
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL_PRIMARY",
      status: "active",
      authorUserId: MEMBER,
      v3: v3Fields({ varType: "url", required: false, description: "" }),
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
    expect(await reissueAuditRows("var.schema_reissued")).toHaveLength(0);
    const renamed = await reissueAuditRows("var.renamed");
    expect(renamed).toHaveLength(1);
    expect(JSON.parse(String(renamed[0]?.["payload"]))).toMatchObject({
      name: "DATABASE_URL_PRIMARY",
    });
  });

  it("a v3 re-issuance on a v1 variable is accepted under enabled (migration at a natural opportunity)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v3: v3Fields({ varType: "url" }),
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
    expect(await reissueAuditRows("var.renamed")).toHaveLength(0);
    expect(await reissueAuditRows("var.schema_reissued")).toHaveLength(1);
  });

  it("relaxing locked to enabled lifts only the creation-time check: existing variables continue and a creation without varType is accepted again (reversibility)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("locked", OWNER);
    await createVariableV3Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
      schema: { varType: "url" },
    }).then((response) => expect(response.status).toBe(200));
    const lockedOut = await declareVariableRequest({
      variableId: "var-untyped",
      name: "UNTYPED_KEY",
      actorUserId: MEMBER,
      schema: { varType: "" },
    });
    expect(lockedOut.status).toBe(422);
    await setSchemaPolicyOk("enabled", OWNER);
    const rename = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
      v3: v3Fields({ varType: "url" }),
    });
    const renameBundle = await manifestForStatement(rename, MEMBER);
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: rename, manifest: renameBundle.manifest },
    );
    expect(renamed.status).toBe(204);
    varStatements.set(VAR, { statement: rename, authorUserId: MEMBER });
    renameBundle.record();
    await declareVariableOk({
      variableId: "var-untyped",
      name: "UNTYPED_KEY",
      schema: { varType: "" },
    });
  });
});

describe("max age (CRYPTO_SPEC §4.2 layout v3, PF6 R9)", () => {
  it("a creation declaring maxAgeDays is accepted and distributed with the field; a deletion must keep it", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const schema = {
      varType: "url" as const,
      required: true,
      description: "primary database",
      maxAgeDays: 90,
    };
    const statement = await variableStatementV3For({
      authorUserId: MEMBER,
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      schema,
    });
    const value = await encryptValue({
      dek,
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: 1,
      variableId: testVariableId(VAR),
      version: 1,
      plaintext: "postgres://alpha",
      writer: identityOf(MEMBER),
      head: fixture.head,
    });
    const { manifest, record } = await manifestForStatement(statement, MEMBER);
    const created = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement,
      value,
      manifest,
    });
    expect(created.status).toBe(200);
    varStatements.set(VAR, { statement, authorUserId: MEMBER });
    record();
    const metadata = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    const body = (await metadata.json()) as { variables: readonly Record<string, unknown>[] };
    expect(body.variables[0]).toMatchObject({ layoutVersion: 3, varType: "url", maxAgeDays: 90 });

    const altered = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v3: v3Fields({ ...schema, maxAgeDays: 30 }),
    });
    const alteredBundle = await manifestForStatement(altered, MEMBER);
    const rejected = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: altered, manifest: alteredBundle.manifest },
    );
    expect(rejected.status).toBe(422);
    await expect(rejected.json()).resolves.toMatchObject({ field: "maxAgeDays" });
    const kept = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v3: v3Fields(schema),
    });
    const keptBundle = await manifestForStatement(kept, MEMBER);
    const deleted = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: kept, manifest: keptBundle.manifest },
    );
    expect(deleted.status).toBe(204);
  });

  it("a v3 statement without maxAgeDays is 422 payload-mismatch (maxAgeDays) before the signature", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV3Variable(dek);
    const signed = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v3: v3Fields({ varType: "url", required: true, description: "primary database" }),
    });
    const { maxAgeDays: _dropped, ...withoutField } = signed;
    const bundle = await manifestForStatement(signed, MEMBER);
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: withoutField, manifest: bundle.manifest },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({ field: "maxAgeDays" });
  });
});
