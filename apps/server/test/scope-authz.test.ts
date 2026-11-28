import type { ChainOperation } from "@maruhi/crypto";
import { generateDek } from "@maruhi/crypto";
import { testUserId } from "@maruhi/crypto/test-support";
import type { WireEncryptedPayload } from "@maruhi/test-kit";
import {
  addMemberOp,
  changeRoleOp,
  checkpointOp,
  createVariableStatement,
  encryptValue,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEntryAt,
  signManifest,
  signMetaStatement,
  testDekCommitmentHex,
  testEnvironmentId,
  testProjectId,
  testVariableId,
  valuesDigestOf,
  valueSignedBytesHashOf,
  type WireVariableMetaStatement,
  wrapDekTo,
} from "@maruhi/test-kit";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

import { BASE, bearer, JSON_HEADERS } from "./support/auth.ts";
import { identityOf, vectorKeyOf, wrapDekForAll } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
  rotateEnvironmentComposite,
  seedMemberToken,
  storedCheckpointValues,
  tokenOf,
} from "./support/data-fixture.ts";
import {
  aadFor,
  ENV,
  fixture,
  registerDataScenario,
  token,
  unsignedManifest,
  unsignedPayload,
  unsignedVariableStatement,
  VAR,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

const DEV = testUserId("user-devmember-0010");
const DEVADMIN = testUserId("user-devadmin-0011");
const OTHER = "env-other-0002";
const GHOST = "env-ghost-9999";

async function expectForbidden(response: Response, reason: string): Promise<void> {
  expect(response.status).toBe(403);
  expect(((await response.json()) as { reason: string }).reason).toBe(reason);
}

const expectScopeForbidden = (response: Response): Promise<void> =>
  expectForbidden(response, "insufficient-scope");

async function setupListed(): Promise<{ envDek: Uint8Array; otherDek: Uint8Array }> {
  const envDek = await createEnvironmentOk(fixture, ENV, "App");
  const otherDek = await createEnvironmentOk(fixture, OTHER, "Other");
  await seedMemberToken(fixture, DEV, 9010);
  await appendOperation(fixture, OWNER, addMemberOp(identityOf(DEV), "member", [ENV]));
  return { envDek, otherDek };
}

async function createVariableAs(input: {
  readonly writer: string;
  readonly environmentId: string;
  readonly dek: Uint8Array;
  readonly variableId: string;
  readonly name: string;
}): Promise<{ value: WireEncryptedPayload; statement: WireVariableMetaStatement }> {
  const value = await encryptValue({
    dek: input.dek,
    projectId: testProjectId(projectId),
    environmentId: testEnvironmentId(input.environmentId),
    epoch: 1,
    variableId: testVariableId(input.variableId),
    version: 1,
    plaintext: `${input.name}-plaintext`,
    writer: identityOf(input.writer),
    head: fixture.head,
  });
  const statement = await createVariableStatement({
    author: identityOf(input.writer),
    projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: input.name,
    head: fixture.head,
  });
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: input.environmentId,
    issuerUserId: input.writer,
    entry: {
      variableId: input.variableId,
      status: "active",
      metaVersion: 1,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, input.writer),
    },
  });
  const response = await requestJson(
    "POST",
    `/environments/${input.environmentId}/variables`,
    token(input.writer),
    { statement, value, manifest },
  );
  expect(response.status).toBe(200);
  fixture.manifests.set(input.environmentId, state);
  return { value, statement };
}

async function appendRaw(actorUserId: string, operation: ChainOperation): Promise<Response> {
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actor: identityOf(actorUserId),
    operation,
  });
  return SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, actorUserId)) },
    body: JSON.stringify({ parentHeadHashHex: fixture.head.hashHex, entry }),
  });
}

async function checkpointFor(environmentId: string, epoch: number): Promise<ChainOperation> {
  const last = fixture.manifests.get(environmentId);
  if (last === undefined) {
    throw new Error(`no recorded manifest for ${environmentId}`);
  }
  return checkpointOp({
    environmentId,
    epoch,
    manifestVersion: last.manifest.manifestVersion,
    manifestSigHashHex: await manifestSignedBytesHashOf(
      projectId,
      last.manifest,
      last.issuerUserId,
    ),
    valuesDigestHex: await valuesDigestOf(await storedCheckpointValues(environmentId)),
  });
}

function unsignedEnvStatement(environmentId: string, name: string, status: "active") {
  return {
    suite: "maruhi/v1",
    environmentId,
    name,
    status,
    metaVersion: 2,
    prevMetaSigHashHex: "cd".repeat(32),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

describe("scope authorization — reads (§12-3 rows 1-2 / §12-7)", () => {
  it("pull with values and fetching DEKs addressed to self require environment ∈ scope: 200 inside, 403 insufficient-scope outside (and no var.read recorded)", async () => {
    await setupListed();
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(DEV))).status).toBe(200);
    await expectScopeForbidden(await requestJson("GET", `/environments/${OTHER}/pull`, token(DEV)));
    expect((await requestJson("GET", `/environments/${ENV}/deks`, token(DEV))).status).toBe(200);
    await expectScopeForbidden(await requestJson("GET", `/environments/${OTHER}/deks`, token(DEV)));
    const reads = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read' AND actor_user_id = ? AND environment_id = ?",
      DEV,
      OTHER,
    );
    expect(reads[0]?.["n"]).toBe(0);
  });

  it("metadata-only pull and the environment list ignore scope and return no advisory scope field (§12-7)", async () => {
    await setupListed();
    const metadata = await requestJson("GET", `/environments/${OTHER}/pull/metadata`, token(DEV));
    expect(metadata.status).toBe(200);
    const list = await requestJson("GET", "/environments", token(DEV));
    expect(list.status).toBe(200);
    const body = (await list.json()) as { environments: Record<string, unknown>[] };
    expect(body.environments.map((environment) => environment["environmentId"]).toSorted()).toEqual(
      [ENV, OTHER].toSorted(),
    );
    for (const environment of body.environments) {
      expect(Object.keys(environment).toSorted()).toEqual(
        ["currentEpoch", "environmentId", "statement"].toSorted(),
      );
    }
  });
});

describe("scope authorization — writes (§12-3 rows 3-5)", () => {
  it("variable create / push / rename / delete, environment rename, and DEK-wrap registration require environment ∈ scope (403 outside, accepted inside)", async () => {
    const { envDek } = await setupListed();
    const otherAad = (version: number, variableId: string = VAR) =>
      aadFor(1, version, { environmentId: OTHER, variableId: testVariableId(variableId) });
    await expectScopeForbidden(
      await requestJson("POST", `/environments/${OTHER}/variables`, token(DEV), {
        statement: { ...unsignedVariableStatement("var-x", "X"), environmentId: OTHER },
        value: unsignedPayload(otherAad(1, "var-x")),
        manifest: unsignedManifest(OTHER),
      }),
    );
    await expectScopeForbidden(
      await requestJson("POST", `/environments/${OTHER}/variables/${VAR}/versions`, token(DEV), {
        value: unsignedPayload(otherAad(2)),
      }),
    );
    await expectScopeForbidden(
      await requestJson("PATCH", `/environments/${OTHER}/variables/${VAR}`, token(DEV), {
        statement: {
          ...unsignedVariableStatement(VAR, "RENAMED"),
          environmentId: OTHER,
          metaVersion: 2,
          prevMetaSigHashHex: "cd".repeat(32),
        },
        manifest: unsignedManifest(OTHER),
      }),
    );
    await expectScopeForbidden(
      await requestJson("DELETE", `/environments/${OTHER}/variables/${VAR}`, token(DEV), {
        statement: {
          ...unsignedVariableStatement(VAR, "DATABASE_URL"),
          environmentId: OTHER,
          status: "deleted",
          metaVersion: 2,
          prevMetaSigHashHex: "cd".repeat(32),
        },
        manifest: unsignedManifest(OTHER),
      }),
    );
    await expectScopeForbidden(
      await requestJson("PATCH", `/environments/${OTHER}`, token(DEV), {
        statement: unsignedEnvStatement(OTHER, "Renamed", "active"),
        manifest: unsignedManifest(OTHER),
      }),
    );
    await expectScopeForbidden(
      await requestJson("POST", `/environments/${OTHER}/deks`, token(DEV), {
        deks: [
          await wrapDekTo({
            projectId,
            environmentId: OTHER,
            epoch: 1,
            dek: generateDek(),
            recipient: identityOf(DEV),
            signer: identityOf(DEV),
          }),
        ],
      }),
    );
    await createVariableAs({
      writer: DEV,
      environmentId: ENV,
      dek: envDek,
      variableId: "var-dev",
      name: "DEV_ONLY",
    });
  });

  it("environment deletion and DEK-wrap deletion require admin × environment ∈ scope (403 outside for a listed admin)", async () => {
    await setupListed();
    await seedMemberToken(fixture, DEVADMIN, 9011);
    await appendOperation(fixture, OWNER, addMemberOp(identityOf(DEVADMIN), "admin", [ENV]));
    await expectScopeForbidden(await deleteEnvironmentRequest(fixture, OTHER, DEVADMIN));
    await expectScopeForbidden(
      await requestJson("DELETE", `/environments/${OTHER}/deks`, token(DEVADMIN), {
        wraps: [
          {
            epoch: 1,
            recipientClass: "member",
            recipientUserId: OWNER,
            recipientEncPubHex: vectorKeyOf(OWNER).enc_pub_hex,
          },
        ],
      }),
    );
    expect((await deleteEnvironmentRequest(fixture, ENV, DEVADMIN)).status).toBe(204);
  });

  it("judgment order: role 403 → scope 403 → existence 404 (a nonexistent environment is also 403 for a listed principal; 404 for an `all` principal)", async () => {
    await setupListed();
    await expectForbidden(await deleteEnvironmentRequest(fixture, OTHER, DEV), "insufficient-role");
    await expectScopeForbidden(await requestJson("GET", `/environments/${GHOST}/pull`, token(DEV)));
    const ghostRotate = await rotateEnvironmentComposite(fixture, {
      environmentId: GHOST,
      newEpoch: 2,
      deks: [],
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: DEV,
    });
    await expectScopeForbidden(ghostRotate);
    expect((await requestJson("GET", `/environments/${GHOST}/pull`, token(MEMBER))).status).toBe(
      404,
    );
  });
});

describe("scope authorization — paths involving a chain op (§9-2 / §12-3 row 4; the 403 precedes the consensus-rule 422 — K3-G)", () => {
  it("environment creation requires scope = all (listed member / admin get 403); rotate requires environment ∈ scope", async () => {
    await setupListed();
    const creation = await createEnvironmentComposite(fixture, {
      environmentId: "env-new-0003",
      name: "New",
      deks: await wrapDekForAll({
        projectId,
        environmentId: "env-new-0003",
        epoch: 1,
        dek: generateDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: DEV,
      }),
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: DEV,
    });
    await expectScopeForbidden(creation);
    const otherRotate = await rotateEnvironmentComposite(fixture, {
      environmentId: OTHER,
      newEpoch: 2,
      deks: [],
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: DEV,
    });
    await expectScopeForbidden(otherRotate);
    const dek = generateDek();
    const rotated = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek,
        recipientUserIds: [...ALL_MEMBERS, DEV],
        signerUserId: DEV,
      }),
      dekCommitmentHex: await testDekCommitmentHex(projectId, ENV, 2, dek),
      actorUserId: DEV,
    });
    expect(rotated.status).toBe(200);
  });

  it("a standalone checkpoint requires every tuple's environment ∈ scope (a tuple outside scope is 403; all-inside is accepted)", async () => {
    await setupListed();
    await expectScopeForbidden(await appendRaw(DEV, await checkpointFor(OTHER, 1)));
    await appendOperation(fixture, DEV, await checkpointFor(ENV, 1));
  });
});

describe("the scope axis of the dual judgment at authorization time (§12-3 / CRYPTO_SPEC §6.3's 3′ — K3-B)", () => {
  it("a value / meta / manifest that is inside scope at acceptance time but outside scope at the declared head is 422 chain-head-state-mismatch (same fold as the role axis)", async () => {
    const { otherDek } = await setupListed();
    const created = await createVariableAs({
      writer: OWNER,
      environmentId: OTHER,
      dek: otherDek,
      variableId: "var-o",
      name: "OTHER_SECRET",
    });
    const oldHead = { ...fixture.head };
    await appendOperation(fixture, OWNER, changeRoleOp({ userId: DEV }, "member", [ENV, OTHER]));

    const stale = await encryptValue({
      dek: otherDek,
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(OTHER),
      epoch: 1,
      variableId: testVariableId("var-o"),
      version: 2,
      plaintext: "stale-head",
      writer: identityOf(DEV),
      head: oldHead,
      prevValueSigHashHex: await valueSignedBytesHashOf(created.value, OWNER),
    });
    const staleValue = await requestJson(
      "POST",
      `/environments/${OTHER}/variables/var-o/versions`,
      token(DEV),
      { value: stale },
    );
    expect(staleValue.status).toBe(422);
    expect(((await staleValue.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    const staleStatement = await signMetaStatement(identityOf(DEV), projectId, {
      suite: "maruhi/v1" as const,
      environmentId: OTHER,
      variableId: "var-o",
      name: "OTHER_SECRET_RENAMED",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, created.statement, OWNER),
      chainHeadHashHex: oldHead.hashHex,
      chainHeadSeq: oldHead.seq,
    });
    const { manifest: freshManifest } = await manifestForVariableOp(fixture, {
      environmentId: OTHER,
      issuerUserId: DEV,
      entry: {
        variableId: "var-o",
        status: "active",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, staleStatement, DEV),
      },
    });
    const staleMeta = await requestJson(
      "PATCH",
      `/environments/${OTHER}/variables/var-o`,
      token(DEV),
      { statement: staleStatement, manifest: freshManifest },
    );
    expect(staleMeta.status).toBe(422);
    expect(((await staleMeta.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    const freshStatement = await signMetaStatement(identityOf(DEV), projectId, {
      ...staleStatement,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const { manifest: baseManifest } = await manifestForVariableOp(fixture, {
      environmentId: OTHER,
      issuerUserId: DEV,
      entry: {
        variableId: "var-o",
        status: "active",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, freshStatement, DEV),
      },
    });
    const { signatureHex: _signatureHex, ...unsignedManifestBody } = baseManifest;
    const staleManifest = await signManifest(identityOf(DEV), projectId, {
      ...unsignedManifestBody,
      chainHeadHashHex: oldHead.hashHex,
      chainHeadSeq: oldHead.seq,
    });
    const staleManifestResponse = await requestJson(
      "PATCH",
      `/environments/${OTHER}/variables/var-o`,
      token(DEV),
      { statement: freshStatement, manifest: staleManifest },
    );
    expect(staleManifestResponse.status).toBe(422);
    expect(((await staleManifestResponse.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    const fresh = await encryptValue({
      dek: otherDek,
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(OTHER),
      epoch: 1,
      variableId: testVariableId("var-o"),
      version: 2,
      plaintext: "fresh-head",
      writer: identityOf(DEV),
      head: fixture.head,
      prevValueSigHashHex: await valueSignedBytesHashOf(created.value, OWNER),
    });
    const freshValue = await requestJson(
      "POST",
      `/environments/${OTHER}/variables/var-o/versions`,
      token(DEV),
      { value: fresh },
    );
    expect(freshValue.status).toBe(200);
  });
});

describe("a request signed over the view from before a delete_environment is stale (409), not out of scope (AUTH_SPEC §12-5's check-order rule)", () => {
  let preDeletionHead: { seq: number; hashHex: string };

  async function deleteEnv(): Promise<void> {
    preDeletionHead = { ...fixture.head };
    expect((await deleteEnvironmentRequest(fixture, ENV, OWNER)).status).toBe(204);
  }

  async function sendOverPreDeletionHead(send: () => Promise<Response>): Promise<Response> {
    const current = fixture.head;
    fixture.head = preDeletionHead;
    try {
      return await send();
    } finally {
      fixture.head = current;
    }
  }

  async function expectStale(response: Response): Promise<void> {
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({ _tag: "ChainHeadConflict" });
  }

  it("a rotate composite is a 409 for an all-scope and a listed-scope rotator (the deletion pruned the listed scope)", async () => {
    await setupListed();
    await deleteEnv();
    for (const actorUserId of [MEMBER, DEV]) {
      await expectStale(
        await sendOverPreDeletionHead(() =>
          rotateEnvironmentComposite(fixture, {
            environmentId: ENV,
            newEpoch: 2,
            deks: [],
            dekCommitmentHex: "ab".repeat(32),
            actorUserId,
          }),
        ),
      );
    }
  });

  it("a standalone checkpoint naming the deleted environment is a 409 for a listed-scope signer", async () => {
    await setupListed();
    const checkpoint = await checkpointFor(ENV, 1);
    await deleteEnv();
    await expectStale(await sendOverPreDeletionHead(() => appendRaw(DEV, checkpoint)));
  });
});
