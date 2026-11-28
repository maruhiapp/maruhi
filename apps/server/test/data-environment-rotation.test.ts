import { generateDek } from "@maruhi/crypto";
import type { WireEncryptedPayload } from "@maruhi/test-kit";
import {
  checkpointOp,
  createEnvironmentOp,
  encryptValue,
  signEntryAt,
  testDekCommitmentHex,
  testEnvironmentId,
  testProjectId,
  testVariableId,
  unwrapAndDecrypt,
  valuesDigestOf,
  valueSignedBytesHashOf,
} from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import { identityOf, wrapDekForAll } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentComposite,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentComposite,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  ENV,
  fakePayload,
  fixture,
  registerDataScenario,
  token,
  VAR,
  wrapsFor,
} from "./support/data-scenario.ts";

registerDataScenario();
describe("epochs and rotation (§12-4 composite / §12-5 / §12-6 / CRYPTO_SPEC §7)", () => {
  it("accepts pushes only under the current chain epoch and completes the composite rotation flow", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const varV1 = await createVariableOk(dek1, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek1, "var-static", "STATIC_KEY", "static-secret");

    const early = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(2, 2)) },
    );
    expect(early.status).toBe(409);
    await expect(early.json()).resolves.toMatchObject({ currentEpoch: 1 });

    const dek2 = generateDek();
    const headBefore = fixture.head;
    const partial = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: [OWNER],
      signerUserId: MEMBER,
    });
    const rejected = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: partial,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(rejected.status).toBe(422);
    expect(((await rejected.json()) as { reason: string }).reason).toBe("recipient-missing");
    const chainAfterRejection = await requestJson("GET", "/chain", token(READER));
    expect(((await chainAfterRejection.json()) as { headSeq: number }).headSeq).toBe(
      headBefore.seq,
    );

    const complete = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const rotation = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: complete,
      dekCommitmentHex: await testDekCommitmentHex(projectId, ENV, 2, dek2),
    });
    expect(rotation.status).toBe(200);
    await expect(rotation.clone().json()).resolves.toMatchObject({
      environmentId: ENV,
      currentEpoch: 2,
      headSeq: headBefore.seq + 2,
    });

    const stale = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(stale.status).toBe(409);
    await expect(stale.json()).resolves.toMatchObject({ currentEpoch: 2 });

    const overwrite = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: generateDek(),
        recipientUserIds: [READER],
        signerUserId: MEMBER,
      }),
    });
    expect(overwrite.status).toBe(409);
    const overwriteBody = (await overwrite.json()) as { epoch: number; recipientUserId: string };
    expect(overwriteBody).toMatchObject({ epoch: 2, recipientUserId: READER });

    const future = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 3,
        dek: generateDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
    });
    expect(future.status).toBe(422);
    expect(((await future.json()) as { reason: string }).reason).toBe("epoch-out-of-range");

    const v2 = await encryptValue({
      dek: dek2,
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: 2,
      variableId: testVariableId(VAR),
      version: 2,
      plaintext: "postgres://rotated",
      writer: identityOf(MEMBER),
      head: fixture.head,
      prevValueSigHashHex: await valueSignedBytesHashOf(varV1, MEMBER),
    });
    const pushed = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: v2 },
    );
    expect(pushed.status).toBe(200);
    await expect(pushed.json()).resolves.toEqual({ variableId: VAR, version: 2, epoch: 2 });

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      currentEpoch: number;
      variables: { variableId: string; value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    expect(body.currentEpoch).toBe(2);
    expect(body.deks.map((wrap) => wrap.epoch)).toEqual([1, 2]);
    const rotated = body.variables.find((v) => v.variableId === VAR);
    const kept = body.variables.find((v) => v.variableId === "var-static");
    if (rotated === undefined || kept === undefined) throw new Error("missing pulled variables");
    expect(rotated.value.aad.epoch).toBe(2);
    expect(kept.value.aad.epoch).toBe(1);
    const dekByEpoch = new Map(body.deks.map((wrap) => [wrap.epoch, wrap]));
    const wrap1 = dekByEpoch.get(1);
    const wrap2 = dekByEpoch.get(2);
    if (wrap1 === undefined || wrap2 === undefined) throw new Error("missing dek wraps");
    await expect(
      unwrapAndDecrypt({
        recipient: identityOf(READER),
        wrapped: wrap2,
        projectId,
        environmentId: ENV,
        payload: rotated.value,
      }),
    ).resolves.toBe("postgres://rotated");
    await expect(
      unwrapAndDecrypt({
        recipient: identityOf(READER),
        wrapped: wrap1,
        projectId,
        environmentId: ENV,
        payload: kept.value,
      }),
    ).resolves.toBe("static-secret");
  });

  it('rejects a rotation to a deleted environment with 404 (§12-4: §7\'s "all environments" does not include deleted ones)', async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const removed = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removed.status).toBe(204);
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: generateDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(404);
    expect(((await response.json()) as { environmentId: string }).environmentId).toBe(ENV);
  });

  it("rejects a rotation to an environment that was never created with 404", async () => {
    const deks = await wrapDekForAll({
      projectId,
      environmentId: "env-ghost-9999",
      epoch: 2,
      dek: generateDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: "env-ghost-9999",
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(404);
  });

  it("rejects an out-of-sequence rotation with 422 chain-entry-invalid (epoch-out-of-sequence)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 3,
      dek: generateDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 3,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("epoch-out-of-sequence");
  });

  it("rejects a rotation whose URL and entry name different environments (422 PayloadMismatch)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, "env-app-0002", "Staging");
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: generateDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
      urlEnvironmentId: "env-app-0002",
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { field: string }).field).toBe("environmentId");
  });

  it("rejects composite wraps whose epoch differs from the entry's new epoch (422 epoch-out-of-range)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const headBefore = fixture.head;
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: generateDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("epoch-out-of-range");
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);
    const list = await requestJson("GET", "/environments", token(READER));
    const listBody = (await list.json()) as { environments: { currentEpoch: number }[] };
    expect(listBody.environments[0]?.currentEpoch).toBe(1);
  });

  it("retries a composite rotation after a head CAS conflict (the §12-4 re-sign retry)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = generateDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const stale = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
      parentHeadHashHex: projectId,
    });
    expect(stale.status).toBe(409);
    const staleBody = (await stale.json()) as { currentHeadHashHex: string };
    expect(staleBody.currentHeadHashHex).toBe(fixture.head.hashHex);
    const retried = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(retried.status).toBe(200);
  });
});

const shapeCheckpoint = async (tuple: {
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly auditHeadHashHex?: string;
}) => {
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 2,
    prevHashHex: "ab".repeat(32),
    actor: identityOf(OWNER),
    operation: checkpointOp({
      ...tuple,
      manifestSigHashHex: "cd".repeat(32),
      valuesDigestHex: await valuesDigestOf([]),
    }),
  });
  return entry;
};

const createWithCheckpoint = async (checkpoint: Awaited<ReturnType<typeof shapeCheckpoint>>) =>
  createEnvironmentComposite(fixture, {
    environmentId: ENV,
    name: "App",
    deks: await wrapsFor(ENV, [...ALL_MEMBERS]),
    dekCommitmentHex: await testDekCommitmentHex(projectId, ENV, 1, generateDek()),
    checkpoint,
  });

const expectPayloadMismatch = async (response: Response, field: string) => {
  expect(response.status).toBe(422);
  expect(((await response.json()) as { field: string }).field).toBe(field);
};

describe("in-composite consistency of a boundary checkpoint (§12-4 / CRYPTO_SPEC §4.3 (2))", () => {
  it("rejects a tuple naming another environment (payload-mismatch checkpointEnvironment)", async () => {
    const response = await createWithCheckpoint(
      await shapeCheckpoint({ environmentId: "env-other-0009", epoch: 1, manifestVersion: 1 }),
    );
    await expectPayloadMismatch(response, "checkpointEnvironment");
  });

  it("rejects a tuple whose epoch differs from the established epoch (checkpointEpoch)", async () => {
    const response = await createWithCheckpoint(
      await shapeCheckpoint({ environmentId: ENV, epoch: 2, manifestVersion: 1 }),
    );
    await expectPayloadMismatch(response, "checkpointEpoch");
  });

  it("rejects a tuple whose manifestVersion differs from the bundled manifest (checkpointManifestVersion)", async () => {
    const response = await createWithCheckpoint(
      await shapeCheckpoint({ environmentId: ENV, epoch: 1, manifestVersion: 2 }),
    );
    await expectPayloadMismatch(response, "checkpointManifestVersion");
  });

  it("rejects a fabricated audit head on a boundary checkpoint (audit-head-unknown)", async () => {
    const response = await createWithCheckpoint(
      await shapeCheckpoint({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 1,
        auditHeadHashHex: "ef".repeat(32),
      }),
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("audit-head-unknown");
  });

  it("rejects a checkpoint whose actor differs from the caller (403 actor-mismatch — §12-4)", async () => {
    const { entry: checkpoint } = await signEntryAt({
      seq: fixture.head.seq + 2,
      prevHashHex: "ab".repeat(32),
      actor: identityOf(MEMBER),
      operation: checkpointOp({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 1,
        manifestSigHashHex: "cd".repeat(32),
        valuesDigestHex: await valuesDigestOf([]),
      }),
    });
    const response = await createWithCheckpoint(checkpoint);
    expect(response.status).toBe(403);
    expect(((await response.json()) as { reason: string }).reason).toBe("actor-mismatch");
  });

  it("rejects a binding whose manifest hash differs from the bundled manifest (422 checkpoint-binding-mismatch)", async () => {
    const commitment = await testDekCommitmentHex(projectId, ENV, 1, generateDek());
    const { hash } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actor: identityOf(OWNER),
      operation: createEnvironmentOp(ENV, commitment),
    });
    const { entry: checkpoint } = await signEntryAt({
      seq: fixture.head.seq + 2,
      prevHashHex: hash,
      actor: identityOf(OWNER),
      operation: checkpointOp({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 1,
        manifestSigHashHex: "ef".repeat(32),
        valuesDigestHex: await valuesDigestOf([]),
      }),
    });
    const response = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks: await wrapsFor(ENV, [...ALL_MEMBERS]),
      dekCommitmentHex: commitment,
      checkpoint,
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe(
      "checkpoint-binding-mismatch",
    );
    const chain = await requestJson("GET", "/chain", token(OWNER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(fixture.head.seq);
  });

  it("rejects a rotate checkpoint whose values digest mismatches the stored enumeration (422 values-digest-mismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapsFor(ENV, [...ALL_MEMBERS], 2, MEMBER),
      dekCommitmentHex: await testDekCommitmentHex(projectId, ENV, 2, generateDek()),
      checkpointValues: [
        {
          variableId: testVariableId("var-phantom-0001"),
          version: 1,
          valueSigHashHex: "ab".repeat(32),
        },
      ],
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("values-digest-mismatch");
  });
});
