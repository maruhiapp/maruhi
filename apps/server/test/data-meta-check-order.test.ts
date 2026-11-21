import { describe, expect, it } from "vite-plus/test";

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
    const conflict = await deleteEnvironmentRequest(fixture, ENV, OWNER, {
      parentHeadHashHex: staleHead.hashHex,
    });
    expect(conflict.status).toBe(409);
    await expect(conflict.json()).resolves.toMatchObject({ _tag: "ChainHeadConflict" });
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
