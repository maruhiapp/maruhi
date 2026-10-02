// Layout v2 (valueless schema) — integration tests of the server-side
// acceptance surface — transitions and layout monotonicity, the
// just-before match of delete statements, and schema re-issuance and
// reversibility (AUTH_SPEC §12-5 / §12-11).

import { describe, expect, it } from "vitest";

import { MAX_SCHEMA_DESCRIPTION_CODEPOINTS } from "../src/policy.ts";
import { encryptValue, signMetaStatementAs, vectorKeyOf } from "./support/data-crypto.ts";
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
  v2Fields,
  VAR,
  variableStatementV2For,
  varStatements,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";
import { createVariableV2Request } from "./support/schema-v2-scenario.ts";

registerDataScenario();

/** Audit rows of the rename path (event name × variable_id — for checking the branch). */
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
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
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
      v2: v2Fields(),
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
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "API_TOKEN",
      status: "declared",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "string", required: false, description: "renamed declaration" }),
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

  it("a v1 successor (rename) on a v2 variable is 422 layout-regression (layout monotonicity)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    }).then((response) => expect(response.status).toBe(200));
    // A v1-layout rename (no schema field — the shape of a silent disappearance)
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
    await setSchemaPolicyOk("enabled", OWNER);
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

/** Create and record a v2 variable (schema field pinned). */
async function seedV2Variable(dek: Uint8Array): Promise<void> {
  await setSchemaPolicyOk("enabled", OWNER);
  const response = await createVariableV2Request({
    variableId: VAR,
    name: "DATABASE_URL",
    plaintext: "postgres://alpha",
    dek,
    schema: { varType: "url", required: true, description: "primary database" },
  });
  expect(response.status).toBe(200);
}

describe("the just-before match of a delete statement's schema field and layout (§12-5)", () => {
  it("a v2 deletion preserving the schema field and layout is 204 (declared deletions share the shape)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV2Variable(dek);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "url", required: true, description: "primary database" }),
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
    // A declared deletion (declared → deleted is allowed — CRYPTO_SPEC §4.2)
    await declareVariableOk({ variableId: "var-declared-del", name: "PENDING_KEY" });
    const declared = varStatements.get("var-declared-del");
    expect(declared).toBeDefined();
    const declaredDelete = await nextVariableStatement({
      variableId: "var-declared-del",
      name: "PENDING_KEY",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v2Fields(),
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
    await seedV2Variable(dek);
    const cases: readonly (readonly [Partial<Parameters<typeof v2Fields>[0]>, string])[] = [
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
        v2: v2Fields(schema),
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
    // Deletion's rule is byte-exact preservation of the stored value,
    // and the description acceptance policy (§12-8) does not apply —
    // applying it would leave existing v2 variables undeletable after a
    // self-host lowers the cap (the "no blocking deletions via the cap"
    // principle). A tampered deletion carrying an over-cap description
    // is caught by preservation's payload-mismatch.
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV2Variable(dek);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v2Fields({
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

  it("a v1-shaped deletion on a v2 variable is 422 payload-mismatch (layoutVersion — the layout is also just-before-matched)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV2Variable(dek);
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
  it("a schema-field-only change on a v2 variable is accepted under the same rules as a rename and reflected in distribution", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
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
      v2: v2Fields({ varType: "url", required: false, description: "connection string" }),
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
    // The audit is var.schema_reissued (a name-unchanged re-issuance —
    // AUDIT_SPEC §3.3. An operation that did not rename is not recorded
    // as var.renamed). It copies the author's key FP, and the payload
    // holds only the name snapshot (the schema field's content is not
    // carried)
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
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
      schema: { varType: "string", required: true, description: "" },
    }).then((response) => expect(response.status).toBe(200));
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL_V2",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "url", required: false, description: "" }),
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
      name: "DATABASE_URL_V2",
    });
  });

  it("a v2 re-issuance on a v1 variable is accepted under enabled (migration at a natural opportunity)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await setSchemaPolicyOk("enabled", OWNER);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "url" }),
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
    // A name-unchanged migration re-issuance is also
    // var.schema_reissued (the branch is a byte comparison of names
    // only — independent of the previous layout)
    expect(await reissueAuditRows("var.renamed")).toHaveLength(0);
    expect(await reissueAuditRows("var.schema_reissued")).toHaveLength(1);
  });

  it("after downgrading to disabled, continuing an already-v2 variable (rename, delete) is still accepted and only new adoption stops (reversibility)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    }).then((response) => expect(response.status).toBe(200));
    await setSchemaPolicyOk("disabled", OWNER);
    // Continuation 1: a v2 rename passes
    const rename = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields(),
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
    // Continuation 2: a v2 deletion also passes (the downgrade does not freeze existing v2 variables' lifecycle)
    const remove = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v2Fields(),
    });
    const removeBundle = await manifestForStatement(remove, MEMBER);
    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: remove, manifest: removeBundle.manifest },
    );
    expect(removed.status).toBe(204);
    removeBundle.record();
    // New adoption stops
    const declared = await declareVariableRequest({
      variableId: "var-new-decl",
      name: "NEW_KEY",
      actorUserId: MEMBER,
    });
    expect(declared.status).toBe(422);
  });
});

describe("layout v3 — expiring values (CRYPTO_SPEC §4.2 layout v3, PF6 R9)", () => {
  it("a v3 creation declaring maxAgeDays is accepted and distributed with the field; a v3 deletion must keep it", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    const statement = await variableStatementV2For({
      authorUserId: MEMBER,
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      schema: { varType: "url", required: true, description: "primary database" },
    });
    const v3 = await signMetaStatementAs(MEMBER, projectId, {
      ...statement,
      ...v3Fields({ varType: "url", required: true, description: "primary database" }, 90),
    });
    const value = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 1 },
      "postgres://alpha",
      { writerUserId: MEMBER, head: fixture.head },
    );
    const { manifest, record } = await manifestForStatement(v3, MEMBER);
    const created = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: v3,
      value,
      manifest,
    });
    expect(created.status).toBe(200);
    varStatements.set(VAR, { statement: v3, authorUserId: MEMBER });
    record();
    const metadata = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    const body = (await metadata.json()) as { variables: readonly Record<string, unknown>[] };
    expect(body.variables[0]).toMatchObject({ layoutVersion: 3, varType: "url", maxAgeDays: 90 });

    // A deletion altering maxAgeDays is a just-before-match 422 (field maxAgeDays)
    const altered = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v3Fields({ varType: "url", required: true, description: "primary database" }, 30),
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
    // Keeping it is 204
    const kept = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v3Fields({ varType: "url", required: true, description: "primary database" }, 90),
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

  it("a v2 → v3 reissue is accepted (the layout rises); a v2 successor on a v3 variable is 422 layout-regression", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV2Variable(dek);
    const upgrade = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v3Fields({ varType: "url", required: true, description: "primary database" }, null),
    });
    const bundle = await manifestForStatement(upgrade, MEMBER);
    const upgraded = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: upgrade, manifest: bundle.manifest },
    );
    expect(upgraded.status).toBe(204);
    varStatements.set(VAR, { statement: upgrade, authorUserId: MEMBER });
    bundle.record();
    const metadata = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    const body = (await metadata.json()) as { variables: readonly Record<string, unknown>[] };
    expect(body.variables[0]).toMatchObject({ layoutVersion: 3, maxAgeDays: null, metaVersion: 2 });

    const regression = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "url", required: true, description: "primary database" }),
    });
    const regressionBundle = await manifestForStatement(regression, MEMBER);
    const rejected = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: regression, manifest: regressionBundle.manifest },
    );
    expect(rejected.status).toBe(422);
    await expect(rejected.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "layout-regression",
    });
  });

  it("the layout ↔ field coupling: a v3 statement without maxAgeDays, or a v2 one with it, is 422 payload-mismatch (maxAgeDays)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV2Variable(dek);
    // The signing API refuses both shapes (InvalidInput), so each is a
    // validly signed statement whose layout / field was altered afterwards
    // — the server's shape check settles before the signature
    const schema = { varType: "url" as const, required: true, description: "primary database" };
    const signedV2 = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields(schema),
    });
    const signedV3 = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v3Fields(schema, 90),
    });
    const { maxAgeDays: _dropped, ...v3WithoutField } = signedV3;
    // The manifest is bundled from the well-formed statement (no hash exists
    // for an ill-shaped one); the shape check settles before the manifest
    for (const [statement, wellFormed] of [
      [{ ...signedV2, layoutVersion: 3 }, signedV2],
      [{ ...signedV2, maxAgeDays: 90 }, signedV2],
      [v3WithoutField, signedV3],
    ] as const) {
      const bundle = await manifestForStatement(wellFormed, MEMBER);
      const response = await requestJson(
        "PATCH",
        `/environments/${ENV}/variables/${VAR}`,
        token(MEMBER),
        { statement, manifest: bundle.manifest },
      );
      expect(response.status).toBe(422);
      await expect(response.json()).resolves.toMatchObject({ field: "maxAgeDays" });
    }
  });
});
