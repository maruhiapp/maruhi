import type { ChainEntry } from "@maruhi/crypto";
import { describe, expect, it } from "vite-plus/test";

import type { DekWrapInput } from "../src/data.package/index.ts";
import { toManifestInput, toMetaStatementInput } from "../src/data.package/index.ts";
import {
  commitmentOf,
  digestOf,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEnvManifestAs,
  signMetaStatementAs,
  wrapDekForAll,
  testVariableId,
} from "./support/data-crypto.ts";
import { testEnvironmentId } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentComposite,
  createEnvironmentOk,
  createEnvironmentStatement,
  deleteEnvironmentRequest,
  envMetaOf,
  MEMBER,
  nextEnvironmentManifest,
  OWNER,
  projectId,
  READER,
  renameEnvironmentRequest,
  requestJson,
  rotateCompositeBody,
  rotateEnvironmentComposite,
  rotateEnvironmentOk,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fakePayload,
  fixture,
  hashOf,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  renameVariableRequest,
  token,
  unsignedManifest,
  VAR,
  variableStatementFor,
  varStatements,
  wrapsFor,
} from "./support/data-scenario.ts";
import { callProjectDo, queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

interface WireManifestBody {
  readonly manifest: {
    readonly environmentId: string;
    readonly epoch: number;
    readonly manifestVersion: number;
    readonly variablesDigestHex: string;
    readonly envMetaVersion: number;
    readonly issuerUserId: string;
    readonly issuerKeyFingerprintHex: string;
  };
}

async function manifestRows(): Promise<readonly Record<string, unknown>[]> {
  return queryProjectDo(
    projectId,
    "SELECT environment_id, manifest_version, epoch, variables_digest_hex, issuer_user_id FROM environment_manifests ORDER BY environment_id",
  );
}

describe("composite acceptance of the environment manifest (§12-5 = CRYPTO_SPEC §4.3)", () => {
  it("issues v1 on creation and re-issues on every meta op, keeping only the latest row (§12-5 / §12-8)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    expect(await manifestRows()).toEqual([
      {
        environment_id: ENV,
        manifest_version: 1,
        epoch: 1,
        variables_digest_hex: await digestOf([]),
        issuer_user_id: OWNER,
      },
    ]);

    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const afterCreate = await manifestRows();
    expect(afterCreate.length).toBe(1);
    expect(afterCreate[0]).toMatchObject({ manifest_version: 2, epoch: 1, issuer_user_id: MEMBER });

    expect((await renameVariableRequest(VAR, "DB_URL", MEMBER)).status).toBe(204);
    expect((await deleteVariableRequest(VAR, MEMBER)).status).toBe(204);
    expect((await renameEnvironmentRequest(fixture, ENV, "App2", MEMBER)).status).toBe(204);
    const rows = await manifestRows();
    expect(rows.length).toBe(1);
    expect(rows[0]).toMatchObject({ manifest_version: 5, epoch: 1 });
    const recorded = fixture.manifests.get(ENV);
    if (recorded === undefined) throw new Error("missing recorded manifest");
    expect(recorded.entries).toEqual([
      expect.objectContaining({ variableId: VAR, status: "deleted", metaVersion: 3 }),
    ]);
    expect(rows[0]?.["variables_digest_hex"]).toBe(await digestOf(recorded.entries));
  });

  it("distributes the latest manifest with issuer info in both pull modes (§12-7)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await deleteVariableRequest(VAR, MEMBER);

    for (const path of [`/environments/${ENV}/pull`, `/environments/${ENV}/pull/metadata`]) {
      const response = await requestJson("GET", path, token(READER));
      expect(response.status).toBe(200);
      const body = (await response.json()) as WireManifestBody;
      expect(body.manifest).toMatchObject({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 3,
        variablesDigestHex: fixture.manifests.get(ENV)?.manifest.variablesDigestHex,
        issuerUserId: MEMBER,
      });
      expect(body.manifest).toHaveProperty("issuerKeyFingerprintHex");
      expect(body.manifest).not.toHaveProperty("signedBytesHashHex");
    }
  });

  it("recomputes the digest server-side: omitting the new variable or the tombstone is 422 manifest-digest-mismatch (§12-5 (7))", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");

    const statement = await variableStatementFor(MEMBER, VAR, "DATABASE_URL");
    const emptyDigest = await nextEnvironmentManifest(fixture, {
      environmentId: ENV,
      epoch: 1,
      entries: [],
      envMeta: await envMetaOf(fixture, ENV),
      issuerUserId: MEMBER,
      head: fixture.head,
    });
    const omitted = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement,
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: emptyDigest,
    });
    expect(omitted.status).toBe(422);
    await expect(omitted.json()).resolves.toMatchObject({
      _tag: "ManifestRejected",
      reason: "manifest-digest-mismatch",
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT 1 FROM variables WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(rows.length).toBe(0);
    expect((await manifestRows())[0]).toMatchObject({ manifest_version: 1 });

    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const last = varStatements.get(VAR);
    if (last === undefined) throw new Error("missing recorded statement");
    const deleteStatement = await nextVariableStatement({
      variableId: VAR,
      name: last.statement.name,
      status: "deleted",
      authorUserId: MEMBER,
    });
    const tombstoneHidden = await nextEnvironmentManifest(fixture, {
      environmentId: ENV,
      epoch: 1,
      entries: [],
      envMeta: await envMetaOf(fixture, ENV),
      issuerUserId: MEMBER,
      head: fixture.head,
    });
    const hid = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: deleteStatement, manifest: tombstoneHidden },
    );
    expect(hid.status).toBe(422);
    await expect(hid.json()).resolves.toMatchObject({ reason: "manifest-digest-mismatch" });
  });

  it("rejects a manifest bound to a stale env-meta statement (422 manifest-digest-mismatch — §12-5 (7))", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const staleEnvMeta = await nextEnvironmentManifest(fixture, {
      environmentId: ENV,
      epoch: 1,
      entries: [],
      envMeta: await envMetaOf(fixture, ENV),
      issuerUserId: MEMBER,
      head: fixture.head,
    });
    const recorded = fixture.envStatements.get(ENV);
    if (recorded === undefined) throw new Error("missing recorded env statement");
    const renameStatement = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      name: "App2",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(
        projectId,
        recorded.statement,
        recorded.authorUserId,
      ),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const response = await requestJson("PATCH", `/environments/${ENV}`, token(MEMBER), {
      statement: renameStatement,
      manifest: staleEnvMeta,
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({ reason: "manifest-digest-mismatch" });
  });

  it("rejects a manifest whose epoch is not current at the declared head (422 manifest-epoch-mismatch — §12-5 (4))", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const statement = await variableStatementFor(MEMBER, VAR, "DATABASE_URL");
    const staleEpoch = await signEnvManifestAs(MEMBER, projectId, {
      suite: "maruhi/v1",
      environmentId: ENV,
      epoch: 2,
      manifestVersion: 2,
      variablesDigestHex: await digestOf([
        {
          variableId: VAR,
          status: "active",
          metaVersion: 1,
          metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, MEMBER),
        },
      ]),
      envMetaVersion: 1,
      envMetaSigHashHex: (await envMetaOf(fixture, ENV)).sigHashHex,
      prevManifestSigHashHex: await (async () => {
        const last = fixture.manifests.get(ENV);
        if (last === undefined) throw new Error("missing manifest");
        return manifestSignedBytesHashOf(projectId, last.manifest, last.issuerUserId);
      })(),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement,
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: staleEpoch,
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "ManifestRejected",
      reason: "manifest-epoch-mismatch",
    });
  });

  it("enforces the manifestVersion CAS with the number only (409 §12-5 (6))", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
    });
    const stale = await signEnvManifestAs(MEMBER, projectId, {
      suite: "maruhi/v1",
      environmentId: ENV,
      epoch: 1,
      manifestVersion: 4,
      variablesDigestHex: await digestOf([]),
      envMetaVersion: 1,
      envMetaSigHashHex: (await envMetaOf(fixture, ENV)).sigHashHex,
      prevManifestSigHashHex: "cd".repeat(32),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest: stale },
    );
    expect(response.status).toBe(409);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      _tag: "ManifestVersionConflict",
      currentManifestVersion: 2,
    });
    expect(Object.keys(body).filter((key) => key.toLowerCase().includes("hash"))).toEqual([]);
    const rows = await queryProjectDo(
      projectId,
      "SELECT meta_version FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ? ORDER BY meta_version",
      ENV,
      VAR,
    );
    expect(rows.map((row) => row["meta_version"])).toEqual([1]);
  });

  it("rejects a manifest signed by someone other than the caller (422 signature-invalid — §12-5 (1))", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const statement = await variableStatementFor(MEMBER, VAR, "DATABASE_URL");
    const { manifest } = await manifestForStatement(statement, OWNER);
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement,
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest,
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "ManifestRejected",
      reason: "signature-invalid",
    });
  });

  it("requires the manifest on every meta-op path (400 schema) and checks its coordinates (422)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const missing = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
    });
    expect(missing.status).toBe(400);
    const wrongEnv = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: { ...unsignedManifest(), environmentId: "env-other-0002" },
    });
    expect(wrongEnv.status).toBe(422);
    expect(((await wrongEnv.json()) as { field: string }).field).toBe("manifestEnvironmentId");
  });

  it("re-issues the manifest with the new epoch on rotation and retries after a head-CAS conflict (§12-4)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const conflicted = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
      dekCommitmentHex: "ab".repeat(32),
      parentHeadHashHex: "ee".repeat(32),
    });
    expect(conflicted.status).toBe(409);
    expect((await manifestRows())[0]).toMatchObject({ manifest_version: 1, epoch: 1 });

    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    expect((await manifestRows())[0]).toMatchObject({ manifest_version: 2, epoch: 2 });

    const mismatched = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 3,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 3,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
      dekCommitmentHex: "ab".repeat(32),
      manifest: await nextEnvironmentManifest(fixture, {
        environmentId: ENV,
        epoch: 2,
        entries: [],
        envMeta: await envMetaOf(fixture, ENV),
        issuerUserId: MEMBER,
        head: fixture.head,
      }),
    });
    expect(mismatched.status).toBe(422);
    expect(((await mismatched.json()) as { field: string }).field).toBe("manifestEpoch");
  });

  it("requires the creation and rotation composites' manifests to declare the pre-append head (§12-4)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const staleHead = { seq: fixture.head.seq - 1, hashHex: await hashOf(fixture.head.seq - 1) };
    const headBefore = fixture.head.seq;
    const rowsBefore = await manifestRows();

    const otherEnv = "env-app-0002";
    const statement = await createEnvironmentStatement({
      authorUserId: OWNER,
      environmentId: otherEnv,
      name: "Staging",
      head: fixture.head,
    });
    const created = await createEnvironmentComposite(fixture, {
      environmentId: otherEnv,
      name: "Staging",
      deks: await wrapsFor(otherEnv, ALL_MEMBERS),
      dekCommitmentHex: "ab".repeat(32),
      statement,
      manifest: await signEnvManifestAs(OWNER, projectId, {
        suite: "maruhi/v1",
        environmentId: otherEnv,
        epoch: 1,
        manifestVersion: 1,
        variablesDigestHex: await digestOf([]),
        envMetaVersion: statement.metaVersion,
        envMetaSigHashHex: await metaSignedBytesHashOf(projectId, statement, OWNER),
        prevManifestSigHashHex: "",
        chainHeadHashHex: staleHead.hashHex,
        chainHeadSeq: staleHead.seq,
      }),
    });
    expect(created.status).toBe(422);
    expect(((await created.json()) as { field: string }).field).toBe("manifestChainHead");

    const rotated = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
      dekCommitmentHex: "ab".repeat(32),
      manifest: await nextEnvironmentManifest(fixture, {
        environmentId: ENV,
        epoch: 2,
        entries: [],
        envMeta: await envMetaOf(fixture, ENV),
        issuerUserId: MEMBER,
        head: staleHead,
      }),
    });
    expect(rotated.status).toBe(422);
    expect(((await rotated.json()) as { field: string }).field).toBe("manifestChainHead");

    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore);
    expect(await manifestRows()).toEqual(rowsBefore);
  });

  it("answers every read surface with a server fault when the stored manifest row is missing (0.28-draft)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await queryProjectDo(
      projectId,
      "DELETE FROM environment_manifests WHERE environment_id = ?",
      ENV,
    );
    const missingRow = "environment manifest row missing";

    for (const path of [`/environments/${ENV}/pull`, `/environments/${ENV}/pull/metadata`]) {
      const response = await requestJson("GET", path, token(READER));
      expect(response.status, path).toBe(500);
      const body = await response.text();
      expect(body).not.toContain(ENV);
      expect(body).not.toContain("manifestVersion");
    }
    await expect(
      callProjectDo(projectId, (instance) =>
        instance.pullEnvironment({ userId: READER }, testEnvironmentId(ENV)),
      ),
    ).rejects.toThrow(missingRow);
    await expect(
      callProjectDo(projectId, (instance) =>
        instance.pullEnvironmentMetadata({ userId: READER }, testEnvironmentId(ENV)),
      ),
    ).rejects.toThrow(missingRow);

    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
    });
    const metaManifest = await nextEnvironmentManifest(fixture, {
      environmentId: ENV,
      epoch: 1,
      entries: [
        {
          variableId: VAR,
          status: "active" as const,
          metaVersion: statement.metaVersion,
          metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, MEMBER),
        },
      ],
      envMeta: await envMetaOf(fixture, ENV),
      issuerUserId: MEMBER,
      head: fixture.head,
    });
    const metaOp = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest: metaManifest },
    );
    expect(metaOp.status).toBe(500);
    await expect(
      callProjectDo(projectId, (instance) =>
        instance.renameVariable(
          { userId: MEMBER },
          testEnvironmentId(ENV),
          testVariableId(VAR),
          toMetaStatementInput(statement as Parameters<typeof toMetaStatementInput>[0]),
          toManifestInput({
            ...metaManifest,
            environmentId: testEnvironmentId(metaManifest.environmentId),
          }),
        ),
      ),
    ).rejects.toThrow(missingRow);

    const nextDek = makeDek();
    const rotation = {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: nextDek,
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, nextDek),
      manifest: await nextEnvironmentManifest(fixture, {
        environmentId: ENV,
        epoch: 2,
        entries: fixture.manifests.get(ENV)?.entries ?? [],
        envMeta: await envMetaOf(fixture, ENV),
        issuerUserId: MEMBER,
        head: fixture.head,
      }),
    };
    const rotated = await rotateEnvironmentComposite(fixture, rotation);
    expect(rotated.status).toBe(500);
    const rotateBody = await rotateCompositeBody(fixture, rotation);
    await expect(
      callProjectDo(projectId, (instance) =>
        instance.rotateEpoch({ userId: MEMBER }, testEnvironmentId(ENV), {
          parentHeadHashHex: rotateBody.parentHeadHashHex,
          entry: rotateBody.entry as ChainEntry & { readonly op: "rotate_epoch" },
          deks: rotateBody.deks as readonly DekWrapInput[],
          manifest: toManifestInput({
            ...rotateBody.manifest,
            environmentId: testEnvironmentId(rotateBody.manifest.environmentId),
          }),
          checkpoint: rotateBody.checkpoint as ChainEntry & { readonly op: "checkpoint" },
        }),
      ),
    ).rejects.toThrow(missingRow);

    expect(await manifestRows()).toEqual([]);
    const metaRows = await queryProjectDo(
      projectId,
      "SELECT meta_version FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(metaRows.map((row) => row["meta_version"])).toEqual([1]);
    const tail = await queryProjectDo(
      projectId,
      "SELECT entry_json FROM chain_entries ORDER BY seq DESC LIMIT 1",
    );
    expect(JSON.parse(String(tail[0]?.["entry_json"]))["op"]).not.toBe("rotate_epoch");
  });

  it("routes a stale v1 against an initialized environment to the CAS 409", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
    });
    const staleV1 = await signEnvManifestAs(MEMBER, projectId, {
      suite: "maruhi/v1",
      environmentId: ENV,
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: "ab".repeat(32),
      envMetaVersion: 1,
      envMetaSigHashHex: "cd".repeat(32),
      prevManifestSigHashHex: "",
      chainHeadHashHex: projectId,
      chainHeadSeq: 1,
    });
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest: staleV1 },
    );
    expect(response.status).toBe(409);
    expect((await response.json()) as Record<string, unknown>).toMatchObject({
      _tag: "ManifestVersionConflict",
      currentManifestVersion: 2,
    });
  });

  it("cascades the manifest row on environment deletion (§12-4)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    expect((await manifestRows()).length).toBe(1);
    expect((await deleteEnvironmentRequest(fixture, ENV, OWNER)).status).toBe(204);
    expect((await manifestRows()).length).toBe(0);
  });
});
