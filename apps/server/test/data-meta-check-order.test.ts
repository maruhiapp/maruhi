// The meta acceptance check order (AUTH_SPEC §12-5): every check that
// depends on the predecessor state runs after the metaVersion CAS. A
// statement signed over a stale view — here, before a concurrent rename —
// is answered with 409 (the client re-verifies and re-signs), never with a
// predecessor-match 422; a 422 always means a malformed or forged statement.
//
// Each test captures the client's view, lets a concurrent rename land,
// rewinds the fixture's records to the captured view (a stale client), and
// sends the operation. The fixture's records are what the request helpers
// sign from (prev hash, metaVersion, name, manifest), so the rewind
// reproduces exactly what a stale client would sign.

import { describe, expect, it } from "vitest";

import {
  createEnvironmentOk,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  requestJson,
} from "./support/data-fixture.ts";
import type { DataFixture } from "./support/data-fixture.ts";
import {
  activateVariableRequest,
  createVariableOk,
  declareVariableOk,
  deleteVariableRequest,
  ENV,
  fixture,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  renameVariableRequest,
  token,
  v3Fields,
  VAR,
  varStatements,
} from "./support/data-scenario.ts";

registerDataScenario();

/** The client-visible records of one environment and one variable (what the helpers sign from). */
interface View {
  readonly envStatement: NonNullable<ReturnType<DataFixture["envStatements"]["get"]>>;
  readonly manifest: NonNullable<ReturnType<DataFixture["manifests"]["get"]>>;
  readonly varStatement: ReturnType<typeof varStatements.get> | null;
}

function captureView(): View {
  const envStatement = fixture.envStatements.get(ENV);
  const manifest = fixture.manifests.get(ENV);
  if (envStatement === undefined || manifest === undefined) {
    throw new Error("no recorded environment view");
  }
  return { envStatement, manifest, varStatement: varStatements.get(VAR) ?? null };
}

function restoreView(view: View): void {
  fixture.envStatements.set(ENV, view.envStatement);
  fixture.manifests.set(ENV, view.manifest);
  if (view.varStatement !== null && view.varStatement !== undefined) {
    varStatements.set(VAR, view.varStatement);
  }
}

describe("predecessor-dependent meta checks run after the metaVersion CAS (§12-5)", () => {
  it("an environment deletion signed over a stale head is a 409 (a concurrent deletion moved it), and re-signed at the fresh head it is the consensus rule's 422 (§12-4)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const staleHead = fixture.head;
    expect((await deleteEnvironmentRequest(fixture, ENV, OWNER)).status).toBe(204);
    // Signed over the head before the concurrent deletion: the CAS answers
    // first (stale), never the environment's deleted state
    const conflict = await deleteEnvironmentRequest(fixture, ENV, OWNER, {
      parentHeadHashHex: staleHead.hashHex,
    });
    expect(conflict.status).toBe(409);
    await expect(conflict.json()).resolves.toMatchObject({ _tag: "ChainHeadConflict" });
    // Over the fresh head the deletion is wrong, not stale
    const wrong = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(wrong.status).toBe(422);
    await expect(wrong.json()).resolves.toMatchObject({
      _tag: "ChainEntryInvalid",
      reason: "environment-deleted",
    });
  });

  it("a variable deletion signed before a concurrent rename is a 409, and succeeds over the fresh view", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const stale = captureView();
    expect((await renameVariableRequest(VAR, "PRIMARY_DATABASE_URL", MEMBER)).status).toBe(204);
    const fresh = captureView();
    restoreView(stale);
    const conflict = await deleteVariableRequest(VAR, MEMBER);
    expect(conflict.status).toBe(409);
    await expect(conflict.json()).resolves.toMatchObject({
      _tag: "MetaVersionConflict",
      currentMetaVersion: 2,
    });
    restoreView(fresh);
    expect((await deleteVariableRequest(VAR, MEMBER)).status).toBe(204);
  });

  it("an activation signed before a concurrent rename of the declared variable is a 409, and succeeds over the fresh view", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const stale = captureView();
    // A concurrent rename keeps the variable declared (declared → declared)
    const rename = await nextVariableStatement({
      variableId: VAR,
      name: "API_TOKEN",
      status: "declared",
      authorUserId: MEMBER,
      v3: v3Fields(),
    });
    const bundle = await manifestForStatement(rename, MEMBER);
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement: rename,
        manifest: bundle.manifest,
      },
    );
    expect(renamed.status).toBe(204);
    varStatements.set(VAR, { statement: rename, authorUserId: MEMBER });
    bundle.record();
    const fresh = captureView();
    // The stale activation keeps the name "API_KEY" (value version 1 still
    // passes the value CAS — the variable has no value yet)
    restoreView(stale);
    const conflict = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
    });
    expect(conflict.status).toBe(409);
    await expect(conflict.json()).resolves.toMatchObject({
      _tag: "MetaVersionConflict",
      currentMetaVersion: 2,
    });
    restoreView(fresh);
    const activated = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
    });
    expect(activated.status).toBe(200);
  });
});
