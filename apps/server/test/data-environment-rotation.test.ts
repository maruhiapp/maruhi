// Integration tests for the data-plane API (AUTH_SPEC §12) — epochs and
// rotation (§12-4 composite / §12-5 / §12-6 / CRYPTO_SPEC §7) and the
// in-composite consistency of boundary checkpoints (§12-4 / CRYPTO_SPEC
// §4.3 (2)).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
// Environment management and creation-composite DEK-wrap verification
// live in data-environment.test.ts (for the split's motivation see the
// top of support/membership-scenario.ts).

import { describe, expect, it } from "vitest";

import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  checkpointOperation,
  commitmentOf,
  createEnvironmentOperation,
  encryptValue,
  makeDek,
  signEntryAt,
  unwrapAndDecrypt,
  valueSignedBytesHashOf,
  valuesDigestOf,
  wrapDekForAll,
} from "./support/data-crypto.ts";
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

    // A push under a future epoch before rotation is also rejected
    const early = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(2, 2)) },
    );
    expect(early.status).toBe(409);
    await expect(early.json()).resolves.toMatchObject({ currentEpoch: 1 });

    // Rotation is a composite request (§12-4): bundling a subset is a
    // 422 recipient-missing, and no chain entry is appended (atomicity)
    const dek2 = makeDek();
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

    // The complete-set composite rotation → epoch 2 (chain append + wrap registration are atomic)
    const complete = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    // The accepted positive case passes the wrapped DEK's own commitment
    const rotation = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: complete,
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek2),
    });
    expect(rotation.status).toBe(200);
    // The composite appends two entries: rotate (H+1) + boundary checkpoint (H+2) (§12-4)
    await expect(rotation.clone().json()).resolves.toMatchObject({
      environmentId: ENV,
      currentEpoch: 2,
      headSeq: headBefore.seq + 2,
    });

    // A push under the old epoch is a 409 (returns the current epoch — the client re-encrypts and retries)
    const stale = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(stale.status).toBe(409);
    await expect(stale.json()).resolves.toMatchObject({ currentEpoch: 2 });

    // Overwriting an existing (epoch, recipient) is forbidden (409 DekWrapExists)
    const overwrite = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: [READER],
        signerUserId: MEMBER,
      }),
    });
    expect(overwrite.status).toBe(409);
    const overwriteBody = (await overwrite.json()) as { epoch: number; recipientUserId: string };
    expect(overwriteBody).toMatchObject({ epoch: 2, recipientUserId: READER });

    // Registration addressed to a future epoch (3) is a 422 epoch-out-of-range
    const future = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 3,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
    });
    expect(future.status).toBe(422);
    expect(((await future.json()) as { reason: string }).reason).toBe("epoch-out-of-range");

    // Push the value re-encrypted under the new epoch (var-static is
    // kept as-is on the epoch of its time — §7). The declared head = the
    // current head including the rotate entry, prev chains to v1, and the
    // epoch is monotonic (1 → 2) — the §4.1 shape of a rotation execution
    // flow
    const v2 = await encryptValue(
      dek2,
      { projectId, environmentId: ENV, epoch: 2, variableId: VAR, version: 2 },
      "postgres://rotated",
      {
        writerUserId: MEMBER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(varV1, MEMBER),
      },
    );
    const pushed = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: v2 },
    );
    expect(pushed.status).toBe(200);
    await expect(pushed.json()).resolves.toEqual({ variableId: VAR, version: 2, epoch: 2 });

    // pull: the current epoch is 2, and the latest version's epoch
    // differs per variable. Wraps addressed to the caller for every epoch
    // are bundled, so values of both epochs are decryptable client-side
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
        recipientUserId: READER,
        wrapped: wrap2,
        projectId,
        environmentId: ENV,
        payload: rotated.value,
      }),
    ).resolves.toBe("postgres://rotated");
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
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
      dek: makeDek(),
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
    // An environment's existence is chain-derived + a data row (created
    // atomically by the composite). A rotate to a never-created
    // environment is a missing data row = 404 (the unknown-environment
    // consensus rule is pinned by the crypto layer's vectors — on the
    // server the data-row check comes first)
    const deks = await wrapDekForAll({
      projectId,
      environmentId: "env-ghost-9999",
      epoch: 2,
      dek: makeDek(),
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
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    // From current epoch 1, the only valid rotate is to 2 (CRYPTO_SPEC §6.3 — verifyChain is authoritative)
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
    // The in-composite consistency check (§12-4): an entry for one environment × a URL for another is not accepted
    await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, "env-app-0002", "Staging");
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: makeDek(),
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
    // The §12-4 in-composite consistency check: a bundled wrap's epoch =
    // the entry's new_epoch. Even slipping a wrap addressed to epoch 1
    // (an already-registered epoch) into a rotate composite is rejected
    await createEnvironmentOk(fixture, ENV, "App");
    const headBefore = fixture.head;
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: makeDek(),
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
    // Atomicity: no entry is appended either (the epoch stays at 1)
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);
    const list = await requestJson("GET", "/environments", token(READER));
    const listBody = (await list.json()) as { environments: { currentEpoch: number }[] };
    expect(listBody.environments[0]?.currentEpoch).toBe(1);
  });

  it("retries a composite rotation after a head CAS conflict (the §12-4 re-sign retry)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = makeDek();
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
      parentHeadHashHex: projectId, // the genesis hash = a stale head
    });
    expect(stale.status).toBe(409);
    const staleBody = (await stale.json()) as { currentHeadHashHex: string };
    expect(staleBody.currentHeadHashHex).toBe(fixture.head.hashHex);
    // The entry rebuilt (re-signed) against the correct parent head is accepted
    const retried = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(retried.status).toBe(200);
  });
});

/**
 * Build a boundary checkpoint with an arbitrary tuple, signed by OWNER
 * (for the bundled-contents-match negatives). Since the match check runs
 * before chain acceptance verification, a dummy prev is fine (it is
 * never reached).
 */
const shapeCheckpoint = async (tuple: {
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly auditHeadHashHex?: string;
}) => {
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 2,
    prevHashHex: "ab".repeat(32),
    actorUserId: OWNER,
    operation: checkpointOperation({
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
    dekCommitmentHex: await commitmentOf(projectId, ENV, 1, makeDek()),
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
    // A non-empty audit_head_hash is accepted under the §16-2 rule
    // (effective-permission admin + the §6.4 existence / position
    // checks).
    // An attestation absent from the stored cumulative hash column =
    // a fabricated notarization is dropped at the acceptance stage
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
    // The entry, statement, and manifest stay with the calling
    // principal (OWNER); only the checkpoint is MEMBER-signed → violates
    // the strict actor equality across both chain entries
    const { entry: checkpoint } = await signEntryAt({
      seq: fixture.head.seq + 2,
      prevHashHex: "ab".repeat(32),
      actorUserId: MEMBER,
      operation: checkpointOperation({
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
    // Make the coordinates (env / epoch / manifestVersion) match the
    // bundled items, and change only the tuple's manifest_sig_hash: the
    // shape check and chain acceptance pass, but §4.3 (2)'s exact-match
    // binding (acceptEnvManifest — the tuple in post-application
    // history) drops it.
    // The H+1 entry is reconstructed with a deterministic signature from
    // the same material as the fixture, and prev connects to it
    const commitment = await commitmentOf(projectId, ENV, 1, makeDek());
    const { hash } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: createEnvironmentOperation(ENV, commitment),
    });
    const { entry: checkpoint } = await signEntryAt({
      seq: fixture.head.seq + 2,
      prevHashHex: hash,
      actorUserId: OWNER,
      operation: checkpointOperation({
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
    // Atomicity: the rejected composite leaves nothing on the chain
    const chain = await requestJson("GET", "/chain", token(OWNER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(fixture.head.seq);
  });

  it("rejects a rotate checkpoint whose values digest mismatches the stored enumeration (422 values-digest-mismatch)", async () => {
    // The same kind of mismatch as a push concurrent with a declared
    // head's finalization (§12-4): the client re-pulls and retries within
    // bounds. The tuple's digest is built from a variable absent from
    // the stored enumeration
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapsFor(ENV, [...ALL_MEMBERS], 2, MEMBER),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, makeDek()),
      checkpointValues: [
        { variableId: "var-phantom-0001", version: 1, valueSigHashHex: "ab".repeat(32) },
      ],
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("values-digest-mismatch");
  });
});
