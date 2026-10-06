// Integration tests for the data-plane API (AUTH_SPEC §12) — composite
// acceptance of the environment manifest (AUTH_SPEC §12-5 = CRYPTO_SPEC
// §4.3).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
//
// What is pinned: composite acceptance together with meta ops /
// manifestVersion CAS (the 409 carries only the latest number) /
// server-side digest recomputation / retention of only the latest one
// copy / bundling into both pull modes (tombstones included — the
// manifest is a required response field) / the missing-row invariant
// violation (a defect, never an omission or a v1 acceptance) / cascade
// on environment deletion.

import { describe, expect, it } from "vitest";

import {
  commitmentOf,
  digestOf,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEnvManifestAs,
  signMetaStatementAs,
  wrapDekForAll,
} from "./support/data-crypto.ts";
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
import { queryProjectDo } from "./support/project-do.ts";

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
    // Right after creation: manifestVersion 1, empty variable set, epoch 1
    expect(await manifestRows()).toEqual([
      {
        environment_id: ENV,
        manifest_version: 1,
        epoch: 1,
        variables_digest_hex: await digestOf([]),
        issuer_user_id: OWNER,
      },
    ]);

    // Variable creation → v2 (the new variable joins the set). The row is replaced, not accumulated (retention is the latest copy only)
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const afterCreate = await manifestRows();
    expect(afterCreate.length).toBe(1);
    expect(afterCreate[0]).toMatchObject({ manifest_version: 2, epoch: 1, issuer_user_id: MEMBER });

    // rename → v3, delete → v4 (tombstone-including digest), environment rename → v5
    expect((await renameVariableRequest(VAR, "DB_URL", MEMBER)).status).toBe(204);
    expect((await deleteVariableRequest(VAR, MEMBER)).status).toBe(204);
    expect((await renameEnvironmentRequest(fixture, ENV, "App2", MEMBER)).status).toBe(204);
    const rows = await manifestRows();
    expect(rows.length).toBe(1);
    expect(rows[0]).toMatchObject({ manifest_version: 5, epoch: 1 });
    // The digest from v4 onward is the tombstone-including set (an attestation that matched the server's recomputation)
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
        // The digest of the tombstone-including set (§12-7 — the same level in both modes)
        variablesDigestHex: fixture.manifests.get(ENV)?.manifest.variablesDigestHex,
        issuerUserId: MEMBER,
      });
      expect(body.manifest).toHaveProperty("issuerKeyFingerprintHex");
      expect(body.manifest).not.toHaveProperty("signedBytesHashHex");
    }
  });

  it("recomputes the digest server-side: omitting the new variable or the tombstone is 422 manifest-digest-mismatch (§12-5 (7))", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");

    // The variable-creation manifest does not contain the new variable's entry (left as the empty set)
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
    // Atomicity: none of the variable row, statement row, or manifest row advances
    const rows = await queryProjectDo(
      projectId,
      "SELECT 1 FROM variables WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(rows.length).toBe(0);
    expect((await manifestRows())[0]).toMatchObject({ manifest_version: 1 });

    // The deletion manifest drops the tombstone (back to the empty set)
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
    // A form where the environment-rename manifest copies the old
    // envMeta (metaVersion 1) does not match the recomputation after the
    // rename is applied (metaVersion 2)
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
      // The current epoch is 1 — a manifest baking in 2 fails the epoch-consistency check
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
    // The latest is 2. Attesting 4 (with a dummy prev) → 409
    // currentManifestVersion 2. The winner's hash is not carried (the
    // §12-5 409 discipline)
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
    // In the same transaction as the metaVersion CAS: the statement row does not advance either
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
    // MEMBER carries in a manifest signed by OWNER → the verification key is the calling principal
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
    // A missing manifest is a wire-Schema 400
    const missing = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
    });
    expect(missing.status).toBe(400);
    // A coordinate mismatch (manifestEnvironmentId) is a 422 from the worker's self-consistency check
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
    // Parent-head CAS failure (409): the manifest is not accepted and the record does not advance
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

    // Retry (both the entry and the manifest are re-signed against the current head — the fixture handles it)
    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    expect((await manifestRows())[0]).toMatchObject({ manifest_version: 2, epoch: 2 });

    // A rotate composite whose manifest epoch disagrees with new_epoch is a 422 at the in-composite consistency check
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
    // An existing but stale head: the creation entry below the current
    // boundary checkpoint
    const staleHead = { seq: fixture.head.seq - 1, hashHex: await hashOf(fixture.head.seq - 1) };
    const headBefore = fixture.head.seq;
    const rowsBefore = await manifestRows();

    // Creation: the statement declares the current head, the manifest is
    // valid in every field but its declared head
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

    // Rotation: the manifest is the legitimate next one, signed against
    // the stale head
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

    // Atomicity: neither refusal leaves anything on the chain or in the
    // manifest rows
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore);
    expect(await manifestRows()).toEqual(rowsBefore);
  });

  it("answers every read surface with a server fault when the stored manifest row is missing (0.28-draft)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Outside the creation composite an environment always has a stored
    // manifest (§12-4's atomic write — the only writers are the creation
    // composite, meta ops and rotate, the only deleter the deletion
    // cascade). A live manifest-less environment can only come from a
    // corrupted DO or a crafted snapshot — an invariant violation,
    // refused as a defect (500), never a 200 that omits the field
    await queryProjectDo(
      projectId,
      "DELETE FROM environment_manifests WHERE environment_id = ?",
      ENV,
    );

    for (const path of [`/environments/${ENV}/pull`, `/environments/${ENV}/pull/metadata`]) {
      const response = await requestJson("GET", path, token(READER));
      expect(response.status, path).toBe(500);
      // The defect body carries no environment data
      const body = await response.text();
      expect(body).not.toContain(ENV);
      expect(body).not.toContain("manifestVersion");
    }

    // A meta operation is refused the same way (the CAS's latest-0
    // state exists only inside the creation composite — never accepted
    // as v1)
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
    });
    const metaOp = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement,
        manifest: await nextEnvironmentManifest(fixture, {
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
        }),
      },
    );
    expect(metaOp.status).toBe(500);

    // So is the rotate composite (a single DEK for both the wrap and
    // the commitment — the member-directed wrap must open to the DEK
    // the chain's commitment names)
    const nextDek = makeDek();
    const rotated = await rotateEnvironmentComposite(fixture, {
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
    });
    expect(rotated.status).toBe(500);

    // Refused without writing: no manifest row, no meta statement
    // advance, and the chain does not move (the rotate's entry pair is
    // not appended)
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
    // A stale v1 against an initialized environment (latest 2) falls to
    // the CAS 409 (carrying currentManifestVersion), joining the
    // legitimate client's re-fetch / re-sign loop
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
      // The declared head is a position older than the current head (the base chain's head from before creation)
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
