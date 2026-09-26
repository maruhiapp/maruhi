// Integration tests for the data-plane API (AUTH_SPEC §12) — composite
// acceptance of the environment manifest (AUTH_SPEC §12-5 = CRYPTO_SPEC
// §4.3).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
//
// What is pinned: composite acceptance together with meta ops /
// manifestVersion CAS (the 409 carries only the latest number) /
// server-side digest recomputation / retention of only the latest one
// copy / bundling into both pull modes (tombstones included) / cascade
// on environment deletion / the migration path (v1 initialization via a
// rotate for a pre-manifest environment).

import { describe, expect, it } from "vitest";

import {
  commitmentOf,
  digestOf,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEnvManifestAs,
  signMetaStatementAs,
  unwrapDistributedDek,
  wrapDekForAll,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentOk,
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
  stripTrailingCheckpoint,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fakePayload,
  fixture,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  renameVariableRequest,
  token,
  unsignedManifest,
  VAR,
  variableStatementFor,
  varStatements,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

interface WireManifestBody {
  readonly manifest?: {
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

  it("initializes manifestVersion 1 through a rotation for a pre-manifest environment (migration path)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // Simulate an environment created before manifests/checkpoints were
    // introduced: strip the trailing boundary checkpoint from the chain
    // (an old-generation chain has no tuple — nothing for §4.3 (2) to
    // bind to) and delete the stored manifest row too
    await stripTrailingCheckpoint(fixture, ENV);
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await queryProjectDo(
      projectId,
      "DELETE FROM environment_manifests WHERE environment_id = ?",
      ENV,
    );
    // pull answers without a manifest (a transitional state — the client side carries the rejection)
    const pulled = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect((await pulled.json()) as WireManifestBody).not.toHaveProperty("manifest");

    // The rotate composite establishes manifestVersion 1 (prev empty) (CAS initial value = 0)
    const entries = fixture.manifests.get(ENV)?.entries ?? [];
    fixture.manifests.delete(ENV);
    const manifest = await nextEnvironmentManifest(fixture, {
      environmentId: ENV,
      epoch: 2,
      entries,
      envMeta: await envMetaOf(fixture, ENV),
      issuerUserId: MEMBER,
      head: fixture.head,
    });
    expect(manifest.manifestVersion).toBe(1);
    // Use a single DEK for both the wrap and the commitment (with
    // separate makeDek()s the server cannot open the member-directed
    // wrap's plaintext and would still accept, but the distributed
    // new-epoch DEK would not match the chain's commitment — pinning a
    // shape a peer CLI would reject)
    const nextDek = makeDek();
    const response = await rotateEnvironmentComposite(fixture, {
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
      manifest,
    });
    expect(response.status).toBe(200);
    expect((await manifestRows())[0]).toMatchObject({
      manifest_version: 1,
      epoch: 2,
      variables_digest_hex: await digestOf(entries),
    });
    const afterInit = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const afterInitBody = (await afterInit.json()) as WireManifestBody & {
      readonly deks: readonly { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    expect(afterInitBody.manifest).toMatchObject({
      manifestVersion: 1,
      epoch: 2,
    });
    // Don't stop at the server's 200: open the distributed wrap as the
    // recipient (READER) and carry through the §5.2 commitment match —
    // equality with the dek_commitment_hex of the rotate_epoch the chain
    // distributed (pinning the peer CLI's receive path)
    const epoch2Wrap = afterInitBody.deks.find((wrap) => wrap.epoch === 2);
    if (epoch2Wrap === undefined) throw new Error("missing epoch-2 wrap in pull");
    const openedDek = await unwrapDistributedDek({
      recipientUserId: READER,
      wrapped: epoch2Wrap,
      projectId,
      environmentId: ENV,
    });
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainEntries = (
      (await chain.json()) as {
        entries: readonly { op: string; payload: { dekCommitmentHex?: string } }[];
      }
    ).entries;
    const rotateEntry = chainEntries.findLast((entry) => entry.op === "rotate_epoch");
    if (rotateEntry === undefined) throw new Error("missing rotate_epoch entry in chain");
    expect(await commitmentOf(projectId, ENV, 2, openedDek)).toBe(
      rotateEntry.payload.dekCommitmentHex,
    );
  });

  it("pins the declared head of a non-composite v1 bootstrap to the acceptance-time head (§12-5 (6))", async () => {
    // Since a v1 is accepted with no stored manifest (latest 0), the
    // manifestVersion CAS cannot drop a request at 409 even when a
    // rotation intervenes after the declared head — so a v1 on the
    // non-composite path requires declared head = the current head at
    // acceptance, closing off a bootstrap that baked epoch 1 into a
    // pre-rotate head (a stale anchor)
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // Simulate an environment created before manifests/checkpoints were
    // introduced (leaving no tuple on the chain — the same reason as the
    // migration-path test above). Strip both the create and the rotate
    // composites' boundary checkpoints from the tail
    await stripTrailingCheckpoint(fixture, ENV);
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const staleHead = fixture.head;
    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    await stripTrailingCheckpoint(fixture, ENV);
    await queryProjectDo(
      projectId,
      "DELETE FROM environment_manifests WHERE environment_id = ?",
      ENV,
    );
    fixture.manifests.delete(ENV);

    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
    });
    const entries = [
      {
        variableId: VAR,
        status: "active" as const,
        metaVersion: statement.metaVersion,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, MEMBER),
      },
    ];
    // A v1 declaring the pre-rotate head (the position where epoch 1
    // was current) = baking in a stale epoch. The epoch-consistency
    // check (at the declared head) would pass this shape, but the head
    // pinning drops it first
    const stale = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement,
        manifest: await nextEnvironmentManifest(fixture, {
          environmentId: ENV,
          epoch: 1,
          entries,
          envMeta: await envMetaOf(fixture, ENV),
          issuerUserId: MEMBER,
          head: staleHead,
        }),
      },
    );
    expect(stale.status).toBe(422);
    expect(((await stale.json()) as { field: string }).field).toBe("manifestChainHead");

    // A v1 declaring the current head + current epoch at acceptance is
    // accepted (the non-composite-path bootstrap itself stays valid for
    // migration)
    const pinned = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement,
        manifest: await nextEnvironmentManifest(fixture, {
          environmentId: ENV,
          epoch: 2,
          entries,
          envMeta: await envMetaOf(fixture, ENV),
          issuerUserId: MEMBER,
          head: fixture.head,
        }),
      },
    );
    expect(pinned.status).toBe(204);
    expect((await manifestRows())[0]).toMatchObject({ manifest_version: 1, epoch: 2 });
  });

  it("routes a stale v1 against an initialized environment to the CAS 409, not the bootstrap pin", async () => {
    // The pin applies only to a v1 with no anchor established (no stored
    // manifest). A stale v1 against an initialized environment (latest
    // 2) falls not to the 422 (manifestChainHead) but to the CAS 409
    // (carrying currentManifestVersion), joining the legitimate client's
    // re-fetch / re-sign loop
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
