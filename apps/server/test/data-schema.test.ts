// Layout v3 (the schema layout) — integration tests of the valueless
// schema's server-side acceptance surface.
//
// Scope: all items of AUTH_SPEC §12-5 "acceptance of layout v3,
// declared, and activation" + §12-8 (the description acceptance check)
// + §12-11 (schemaPolicy) + §12-7 (declared distribution, advisory
// bundling), plus the boundary of §12-5's 422 error names
// (activation-required / layout-regression / schema-required).
//
// How the suite is split (shared helpers in
// support/schema-scenario.ts; for the split's motivation see the
// top of support/membership-scenario.ts):
// - this file: the schemaPolicy setting, default v3 acceptance, declared
//   creation and activation
// - data-schema-transitions.test.ts: transitions and layout
//   monotonicity, deletions' just-before match, schema re-issuance and
//   reversibility, max age
// - data-schema-locked.test.ts: schema-locked, description,
//   unsupported layouts (the retired layout 2 included)

import { describe, expect, it } from "vitest";

import { encryptValue } from "./support/data-crypto.ts";
import {
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  activateVariableRequest,
  createVariableOk,
  declareVariableOk,
  ENV,
  fixture,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  setSchemaPolicyOk,
  token,
  unsignedManifest,
  v3Fields,
  VAR,
  varStatements,
} from "./support/data-scenario.ts";
import { callProjectDo, queryProjectDo } from "./support/project-do.ts";
import { createVariableV3Request } from "./support/schema-scenario.ts";

registerDataScenario();

/** Audit-row count (event name × variable_id). */
async function auditCount(event: string, variableId?: string): Promise<number> {
  const rows =
    variableId === undefined
      ? await queryProjectDo(
          projectId,
          "SELECT COUNT(*) AS n FROM audit_events WHERE event = ?",
          event,
        )
      : await queryProjectDo(
          projectId,
          "SELECT COUNT(*) AS n FROM audit_events WHERE event = ? AND variable_id = ?",
          event,
          variableId,
        );
  return Number(rows[0]?.["n"]);
}

describe("the schemaPolicy setting (AUTH_SPEC §12-11)", () => {
  it("GET returns the default enabled (read × reader or above). Non-members get a uniform 404", async () => {
    const asReader = await requestJson("GET", "/schema-policy", token(READER));
    expect(asReader.status).toBe(200);
    await expect(asReader.json()).resolves.toEqual({ schemaPolicy: "enabled" });
    const asStranger = await requestJson("GET", "/schema-policy", token(STRANGER));
    expect(asStranger.status).toBe(404);
  });

  it("PUT is admin × admin (204). A change records project.schema_policy_changed with the old and new values", async () => {
    await setSchemaPolicyOk("locked", OWNER);
    const read = await requestJson("GET", "/schema-policy", token(READER));
    await expect(read.json()).resolves.toEqual({ schemaPolicy: "locked" });
    const rows = await queryProjectDo(
      projectId,
      "SELECT actor_type, actor_user_id, actor_key_fingerprint, payload FROM audit_events WHERE event = 'project.schema_policy_changed'",
    );
    expect(rows).toHaveLength(1);
    // actor = the changer themself (type=user). No FP since this
    // config operation carries no signature (AUDIT_SPEC §3.3)
    expect(rows[0]).toMatchObject({
      actor_type: "user",
      actor_user_id: OWNER,
      actor_key_fingerprint: null,
    });
    expect(JSON.parse(String(rows[0]?.["payload"]))).toMatchObject({
      previous: "enabled",
      next: "locked",
    });
  });

  it('a same-value PUT stays 204 and adds no audit row (does not record an unchanged transition as a "change")', async () => {
    // The default is enabled: PUT enabled on a fresh project is unchanged
    await setSchemaPolicyOk("enabled", OWNER);
    expect(await auditCount("project.schema_policy_changed")).toBe(0);
    await setSchemaPolicyOk("locked", OWNER);
    await setSchemaPolicyOk("locked", OWNER);
    expect(await auditCount("project.schema_policy_changed")).toBe(1);
  });

  it("PUT authorization: a chain role of member gets 403, a non-member 404", async () => {
    const asMember = await requestJson("PUT", "/schema-policy", token(MEMBER), {
      schemaPolicy: "locked",
    });
    expect(asMember.status).toBe(403);
    const asStranger = await requestJson("PUT", "/schema-policy", token(STRANGER), {
      schemaPolicy: "locked",
    });
    expect(asStranger.status).toBe(404);
    // The rejection does not change the policy
    const read = await requestJson("GET", "/schema-policy", token(OWNER));
    await expect(read.json()).resolves.toEqual({ schemaPolicy: "enabled" });
  });

  it("a PUT of anything but the two values is a Schema-verification 400 (the removed disabled tier included)", async () => {
    for (const schemaPolicy of ["everything", "disabled"]) {
      const response = await requestJson("PUT", "/schema-policy", token(OWNER), { schemaPolicy });
      expect(response.status, schemaPolicy).toBe(400);
    }
  });

  it("an unknown stored value fails closed (storage corruption — never re-read as the default)", async () => {
    await queryProjectDo(
      projectId,
      "INSERT INTO project_settings (id, schema_policy) VALUES (1, 'disabled')",
    );
    // The rejected DO RPC makes workerd log an "uncaught exception" line
    // even though the worker catches it — expected
    const response = await requestJson("GET", "/schema-policy", token(READER));
    expect(response.status).toBe(500);
    // Any defect would answer the same 500; the direct call on the
    // instance pins which one fires
    await expect(
      callProjectDo(projectId, (instance) => instance.schemaPolicyFor({ userId: READER })),
    ).rejects.toThrow("unexpected schema_policy in stored project settings row");
  });

  it("advisory bundling (§12-7): the environment list, the valued pull, and the metadata-only pull all carry schemaPolicy (not verification material)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("locked", OWNER);
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toMatchObject({ schemaPolicy: "locked" });
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    await expect(pull.json()).resolves.toMatchObject({ schemaPolicy: "locked" });
    const metadata = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    await expect(metadata.json()).resolves.toMatchObject({ schemaPolicy: "locked" });
  });
});

describe("layout v3 is accepted by default — no enablement gate (§12-5 / §12-11)", () => {
  it("a fresh project accepts a value-bundled v3 creation", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const created = await createVariableV3Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    });
    expect(created.status).toBe(200);
  });

  it("a fresh project accepts a v3 re-issuance on a v1 variable", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v3: v3Fields({ varType: "url" }),
    });
    const { manifest } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(204);
  });
});

describe("declared creation and activation (§12-5)", () => {
  it("enabled: declared creation is accepted with no value, recording stored version 0 and var.created (author FP)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await declareVariableOk({
      variableId: VAR,
      name: "API_KEY",
      schema: { varType: "string", required: true, description: "third-party API key" },
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT latest_version, latest_meta_version, deleted_at FROM variables WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    // Stored version stays 0 on an active row (§12-5 — declared is the
    // only legitimate version-0 state. Also counts toward the
    // active-variable cap)
    expect(rows).toEqual([{ latest_version: 0, latest_meta_version: 1, deleted_at: null }]);
    // The interval's start = acceptance of metaVersion 1 (AUDIT_SPEC
    // §3.3 — declared creation is also var.created. With no value
    // signature, the FP is the author key FP of the statement
    // signature)
    const audits = await queryProjectDo(
      projectId,
      "SELECT actor_user_id, actor_key_fingerprint FROM audit_events WHERE event = 'var.created' AND variable_id = ?",
      VAR,
    );
    expect(audits).toHaveLength(1);
    expect(audits[0]?.["actor_user_id"]).toBe(MEMBER);
    expect(typeof audits[0]?.["actor_key_fingerprint"]).toBe("string");
    expect(await auditCount("var.version_pushed", VAR)).toBe(0);
  });

  it("distribution (§12-7): declared appears on the valued pull's declaredVariables and the metadata-only pull's variables; values and DEKs are not carried", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await declareVariableOk({
      variableId: VAR,
      name: "API_KEY",
      schema: { varType: "url", required: false, description: "endpoint" },
    });
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const pulled = (await pull.json()) as {
      variables: readonly unknown[];
      declaredVariables?: readonly Record<string, unknown>[];
    };
    // It does not appear in the values array (the supply side of the
    // status-active value-distribution requirement — CRYPTO_SPEC §6.3 —
    // "declared is the only legitimate valueless state")
    expect(pulled.variables).toEqual([]);
    expect(pulled.declaredVariables).toHaveLength(1);
    // The v3 carrier fields (§12-2) are carried aligned with the statement
    expect(pulled.declaredVariables?.[0]).toMatchObject({
      variableId: VAR,
      status: "declared",
      layoutVersion: 3,
      varType: "url",
      required: false,
      description: "endpoint",
      maxAgeDays: null,
      authorUserId: MEMBER,
    });
    const metadata = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    const metadataBody = (await metadata.json()) as {
      variables: readonly Record<string, unknown>[];
    };
    expect(metadataBody.variables).toHaveLength(1);
    expect(metadataBody.variables[0]).toMatchObject({ variableId: VAR, status: "declared" });
    // Distributing a declared does not record a var.read (no value was distributed — AUDIT_SPEC §3.3)
    expect(await auditCount("var.read", VAR)).toBe(0);
  });

  it("a normal push against a declared is 422 activation-required", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const value = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 1 },
      "secret-value",
      { writerUserId: MEMBER, head: fixture.head },
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "ActivationRequired",
      variableId: VAR,
    });
  });

  it("the activation composite is accepted with 200 version 1 and records var.version_pushed (version 1)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const response = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ variableId: VAR, version: 1, epoch: 1 });
    expect(await auditCount("var.version_pushed", VAR)).toBe(1);
    expect(await auditCount("var.created", VAR)).toBe(1);
    // A pull after activation distributes the value and declaredVariables becomes empty
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const pulled = (await pull.json()) as {
      variables: readonly Record<string, unknown>[];
      declaredVariables?: readonly unknown[];
    };
    expect(pulled.variables).toHaveLength(1);
    expect(pulled.declaredVariables).toBeUndefined();
    // After activation, normal pushes are accepted (the declared gate is lifted)
    const next = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
      "rotated-value",
      {
        writerUserId: MEMBER,
        head: fixture.head,
        prevValueSigHashHex: await storedValueSigHash(VAR, 1),
      },
    );
    const push = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: next },
    );
    expect(push.status).toBe(200);
  });

  it("the activation composite on an active variable is 422 payload-mismatch (status) once it passes the CAS, and a stale-view 409 before (§12-5's check order)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableV3Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    }).then((response) => expect(response.status).toBe(200));
    // Version 1 is a view in which the variable is still unactivated (a
    // stale view — the value CAS answers 409); latest + 1 passes both
    // CASes, so the target judgment against the predecessor (an active
    // variable is not an activation target) answers 422 — the explicit
    // guard, independent of the value CAS (with a version-1-only helper,
    // "cannot target an active variable" could not be verified)
    const stale = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "postgres://beta",
      version: 1,
      prevValueSigHashHex: "",
    });
    expect(stale.status).toBe(409);
    await expect(stale.json()).resolves.toMatchObject({ _tag: "VersionConflict" });
    const response = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "postgres://beta",
      version: 2,
      prevValueSigHashHex: await storedValueSigHash(VAR, 1),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "status",
    });
  });

  it("an active v1 variable cannot be promoted to v3 via the activation path (the activation target is only a declared)", async () => {
    // The status guard keeps a value push to an active variable from
    // riding the activation composite (a version latest+1 passes the
    // value CAS, so the CAS alone cannot reject it)
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const response = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "postgres://beta",
      version: 2,
      prevValueSigHashHex: await storedValueSigHash(VAR, 1),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "status",
    });
    // The rejection writes nothing: the latest statement stays layout 1 and version is unchanged
    const rows = await queryProjectDo(
      projectId,
      `SELECT ms.layout_version, v.latest_version, v.latest_meta_version
       FROM variables v
       JOIN variable_meta_statements ms
         ON ms.environment_id = v.environment_id
        AND ms.variable_id = v.variable_id
        AND ms.meta_version = v.latest_meta_version
       WHERE v.environment_id = ? AND v.variable_id = ?`,
      ENV,
      VAR,
    );
    expect(rows).toEqual([{ layout_version: 1, latest_version: 1, latest_meta_version: 1 }]);
  });

  it("activation does not double as a rename (name keeps the declaration's name — 422 payload-mismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const renamed = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
      name: "API_TOKEN",
    });
    expect(renamed.status).toBe(422);
    await expect(renamed.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "name",
    });
    // Renaming can still reach the same result via the rename path
    // (declared → declared — audited as var.renamed); the capability is
    // not lost
    const rename = await nextVariableStatement({
      variableId: VAR,
      name: "API_TOKEN",
      status: "declared",
      authorUserId: MEMBER,
      v3: v3Fields(),
    });
    const renameBundle = await manifestForStatement(rename, MEMBER);
    const renameResponse = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: rename, manifest: renameBundle.manifest },
    );
    expect(renameResponse.status).toBe(204);
    varStatements.set(VAR, { statement: rename, authorUserId: MEMBER });
    renameBundle.record();
    const activated = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
    });
    expect(activated.status).toBe(200);
  });

  it("the creation composite cannot create a deleted (a wire-shape 400 — §12-5's acceptance surface is authoritative)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // A zero signature valid only in form (a Schema 400 never reaches signature verification)
    const statement = {
      suite: "maruhi/v1",
      environmentId: ENV,
      variableId: VAR,
      name: "API_KEY",
      status: "deleted",
      metaVersion: 1,
      prevMetaSigHashHex: "",
      ...v3Fields(),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
      signatureHex: "00".repeat(64),
    };
    const withoutValue = await requestJson(
      "POST",
      `/environments/${ENV}/variables`,
      token(MEMBER),
      {
        statement,
        manifest: unsignedManifest(),
      },
    );
    expect(withoutValue.status).toBe(400);
  });
});

/** The value signed-bytes hash of a stored version (prev material for the next version). */
async function storedValueSigHash(variableId: string, version: number): Promise<string> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT signed_bytes_hash_hex FROM variable_versions WHERE environment_id = ? AND variable_id = ? AND version = ?",
    ENV,
    variableId,
    version,
  );
  return String(rows[0]?.["signed_bytes_hash_hex"]);
}
