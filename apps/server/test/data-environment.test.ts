// Integration tests for the data-plane API (AUTH_SPEC §12) — environment
// management (the §12-4 composite request) and the creation composite's
// DEK-wrap verification (§12-6).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
// The shared fixture and helpers live in support/data-scenario.ts.
// Epochs/rotation and the in-composite consistency of boundary
// checkpoints live in data-environment-rotation.test.ts (for the split's
// motivation see the top of support/membership-scenario.ts).

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import {
  checkpointOperation,
  commitmentOf,
  makeDek,
  signEntryAt,
  valuesDigestOf,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentComposite,
  createEnvironmentOk,
  createEnvironmentStatement,
  createEnvironmentWith,
  dataUrl,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  renameEnvironmentRequest,
  requestJson,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  unsignedManifest,
  VAR,
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("environment management (the §12-4 composite request)", () => {
  it("creates an environment atomically: chain entry + epoch-1 wrap set + name in one request", async () => {
    const headBefore = fixture.head;
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    // For the positive case, pass the wrapped DEK's own commitment
    const created = await createEnvironmentWith(
      fixture,
      ENV,
      "App",
      deks,
      await commitmentOf(projectId, ENV, 1, dek),
    );
    expect(created.status).toBe(200);
    const body = (await created.json()) as {
      environmentId: string;
      currentEpoch: number;
      headSeq: number;
      headHashHex: string;
    };
    expect(body.environmentId).toBe(ENV);
    expect(body.currentEpoch).toBe(1);
    // The composite appends two entries: create (H+1) + boundary checkpoint (H+2) (§12-4)
    expect(body.headSeq).toBe(headBefore.seq + 2);

    // Two entries, create_environment + checkpoint, have been appended to
    // the chain (one half of the composite's atomicity)
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: { op: string; seq: number }[] };
    expect(chainBody.entries.at(-2)?.op).toBe("create_environment");
    expect(chainBody.entries.at(-1)?.op).toBe("checkpoint");
    expect(chainBody.entries.at(-1)?.seq).toBe(body.headSeq);

    // The environment list returns not a bare name but the latest statement + author info (§12-2)
    const list = await requestJson("GET", "/environments", token(READER));
    expect(list.status).toBe(200);
    const listBody = (await list.json()) as {
      environments: {
        environmentId: string;
        currentEpoch: number;
        statement: {
          name: string;
          status: string;
          metaVersion: number;
          authorUserId: string;
          authorKeyFingerprintHex: string;
        };
      }[];
    };
    expect(listBody.environments.length).toBe(1);
    expect(listBody.environments[0]).toMatchObject({
      environmentId: ENV,
      currentEpoch: 1,
      statement: {
        name: "App",
        status: "active",
        metaVersion: 1,
        authorUserId: OWNER,
        authorKeyFingerprintHex: vectorKeyOf(OWNER).key_fingerprint_hex,
      },
    });

    const wraps = await queryProjectDo(
      projectId,
      "SELECT recipient_user_id FROM dek_wraps WHERE environment_id = ? AND epoch = 1 ORDER BY recipient_user_id",
      ENV,
    );
    expect(wraps.map((row) => row["recipient_user_id"])).toEqual([...ALL_MEMBERS].toSorted());
  });

  it("rejects a duplicate environment id with 422 chain-entry-invalid (duplicate-environment)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    // ID uniqueness is a consensus rule (CRYPTO_SPEC §6.2)
    const response = await createEnvironmentWith(fixture, ENV, "App2", deks);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("duplicate-environment");
    expect(body.seq).toBe(fixture.head.seq + 1);
  });

  it("never reuses a deleted environment id (422 duplicate-environment) and hard-deletes its data", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://old");
    const removed = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removed.status).toBe(204);

    // Variables, variable statements, versions, and wraps are deleted
    // immediately; the environment row becomes a tombstone (§12-4). The
    // environment's own statement chain (including deleted) remains
    for (const table of [
      "variables",
      "variable_meta_statements",
      "variable_versions",
      "dek_wraps",
    ]) {
      const rows = await queryProjectDo(
        projectId,
        `SELECT 1 FROM ${table} WHERE environment_id = ?`,
        ENV,
      );
      expect(rows.length).toBe(0);
    }
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(404);

    // The chain does not observe deletions, so re-creation is rejected
    // by the consensus rule (uniqueness across the whole history)
    // (CRYPTO_SPEC §6.2 / AUTH_SPEC §12-4)
    const recreated = await createEnvironmentWith(fixture, ENV, "App3", []);
    expect(recreated.status).toBe(422);
    const body = (await recreated.json()) as { reason: string };
    expect(body.reason).toBe("duplicate-environment");
  });

  it("rejects create_environment / rotate_epoch on the generic chain append (422 CompositeRequired)", async () => {
    // AUTH_SPEC §6 / §12-4: do not let the generic path bypass the composite endpoint's atomicity
    const { entry: createEntry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: MEMBER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const createResponse = await requestJson("POST", "/chain/entries", token(MEMBER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry: createEntry,
    });
    expect(createResponse.status).toBe(422);
    expect((await createResponse.json()) as { op: string }).toMatchObject({
      op: "create_environment",
    });

    const { entry: rotateEntry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: MEMBER,
      operation: {
        op: "rotate_epoch",
        payload: {
          environmentId: ENV,
          newEpoch: 2,
          reason: "bypass",
          dekCommitmentHex: "ab".repeat(32),
        },
      },
    });
    const rotateResponse = await requestJson("POST", "/chain/entries", token(MEMBER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry: rotateEntry,
    });
    expect(rotateResponse.status).toBe(422);
    expect((await rotateResponse.json()) as { op: string }).toMatchObject({ op: "rotate_epoch" });

    // Neither was appended to the chain
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { headSeq: number };
    expect(chainBody.headSeq).toBe(fixture.head.seq);
  });

  it("retries a composite creation after a head CAS conflict (409 ChainHeadConflict → re-sign → 200)", async () => {
    // §12-4: a parent-head CAS failure requires re-signing the chain
    // entry (a changed prev). Sending with a stale parent (genesis-level)
    // returns a 409 + the current head, and a retry with the correct
    // parent can proceed
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const dekCommitmentHex = await commitmentOf(projectId, ENV, 1, dek);
    const stale = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex,
      parentHeadHashHex: projectId, // the genesis hash = a head two generations stale
    });
    expect(stale.status).toBe(409);
    const staleBody = (await stale.json()) as {
      currentHeadSeq: number;
      currentHeadHashHex: string;
    };
    expect(staleBody.currentHeadSeq).toBe(fixture.head.seq);
    expect(staleBody.currentHeadHashHex).toBe(fixture.head.hashHex);
    // Nothing was written (atomicity: a CAS failure leaves no trace on chain or data)
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toEqual({ environments: [], schemaPolicy: "disabled" });

    // The retried positive case passes the wrapped DEK's own commitment
    const retried = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex,
    });
    expect(retried.status).toBe(200);
  });

  it("enforces display-name uniqueness on create and rename (409 duplicate-name)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: "env-app-0002",
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const commitment = await commitmentOf(projectId, "env-app-0002", 1, dek);
    const duplicate = await createEnvironmentWith(fixture, "env-app-0002", "App", deks, commitment);
    expect(duplicate.status).toBe(409);
    const body = (await duplicate.json()) as { reason: string };
    expect(body.reason).toBe("duplicate-name");

    // For the positive case that proceeds to acceptance (200), pass the wrapped DEK's commitment
    const second = await createEnvironmentWith(
      fixture,
      "env-app-0002",
      "Staging",
      deks,
      commitment,
    );
    expect(second.status).toBe(200);
    const renamed = await renameEnvironmentRequest(fixture, "env-app-0002", "App", MEMBER);
    expect(renamed.status).toBe(409);
    const ok = await renameEnvironmentRequest(fixture, "env-app-0002", "Prod", MEMBER);
    expect(ok.status).toBe(204);
    const list = await requestJson("GET", "/environments", token(READER));
    const listBody = (await list.json()) as {
      environments: { statement: { name: string } }[];
    };
    expect(listBody.environments.map((e) => e.statement.name).toSorted()).toEqual(["App", "Prod"]);
  });

  it("requires chain role admin for environment deletion (§12-3)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const asMember = await deleteEnvironmentRequest(fixture, ENV, MEMBER);
    expect(asMember.status).toBe(403);
    const body = (await asMember.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });

  it("requires chain role member for creation: reader gets 403 insufficient-role", async () => {
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: READER,
    });
    const response = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: READER,
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });

  it("rejects a composite whose entry actor differs from the principal (403 actor-mismatch)", async () => {
    // §12-4: the chain entry's actor must strictly equal the calling principal (the same discipline as §11-1)
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const { entry, hash } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    // The boundary checkpoint is also signed by the same actor (OWNER) —
    // to pass Schema and reach the actor-equality check (403)
    const { entry: checkpoint } = await signEntryAt({
      seq: entry.seq + 1,
      prevHashHex: hash,
      actorUserId: OWNER,
      operation: checkpointOperation({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 1,
        manifestSigHashHex: "ab".repeat(32),
        valuesDigestHex: await valuesDigestOf([]),
      }),
    });
    const response = await requestJson("POST", "/environments", token(MEMBER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      statement: await createEnvironmentStatement({
        authorUserId: OWNER,
        environmentId: ENV,
        name: "App",
        head: fixture.head,
      }),
      deks,
      manifest: unsignedManifest(),
      checkpoint,
    });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { reason: string }).reason).toBe("actor-mismatch");
  });

  it("conceals the project from non-members with 404 (§11-2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    for (const [method, path] of [
      ["GET", "/environments"],
      ["GET", `/environments/${ENV}/pull`],
      ["GET", `/environments/${ENV}/deks`],
    ] as const) {
      const response = await requestJson(method, path, token(STRANGER));
      expect(response.status).toBe(404);
      const body = (await response.json()) as { projectId: string };
      expect(body.projectId).toBe(projectId);
    }
    // Deletion (which requires a statement) is also a 404 for
    // non-members. STRANGER holds no vector key, so it is sent as an
    // unsigned dummy (existence hiding precedes signature verification —
    // §12-3)
    const removal = await requestJson("DELETE", `/environments/${ENV}`, token(STRANGER), {
      statement: {
        suite: "maruhi/v1",
        environmentId: ENV,
        name: "App",
        status: "deleted",
        metaVersion: 2,
        prevMetaSigHashHex: "cd".repeat(32),
        chainHeadHashHex: fixture.head.hashHex,
        chainHeadSeq: fixture.head.seq,
        signatureHex: "00".repeat(64),
      },
    });
    expect(removal.status).toBe(404);
    expect(((await removal.json()) as { projectId: string }).projectId).toBe(projectId);
  });

  it("rejects unauthenticated requests with 401", async () => {
    const response = await SELF.fetch(dataUrl("/environments"));
    expect(response.status).toBe(401);
  });
});

describe("DEK-wrap verification at environment creation (§12-6)", () => {
  it("rejects a wrap set missing a current member (422 recipient-missing)", async () => {
    const deks = await wrapsFor(ENV, [OWNER, MEMBER]);
    const response = await createEnvironmentWith(fixture, ENV, "App", deks);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-missing");
  });

  it("rejects an empty wrap set atomically (§12-4: bundling the epoch-1 complete set is mandatory)", async () => {
    // An empty set would slip past the per-epoch check and create "an
    // environment no one can hold a DEK for". Closed by the explicit
    // check that count = current member count
    const response = await createEnvironmentWith(fixture, ENV, "App", []);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-missing");
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toEqual({ environments: [], schemaPolicy: "disabled" });
    // Composite atomicity (§12-4): a composite that failed the wrap
    // check appends no chain entry either (no "commitment exists but
    // wraps do not" intermediate state)
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { headSeq: number };
    expect(chainBody.headSeq).toBe(fixture.head.seq);
  });

  it("rejects a wrap addressed to a non-member (422 recipient-not-member)", async () => {
    const deks = [
      ...(await wrapsFor(ENV, ALL_MEMBERS)),
      await wrapDekTo({
        projectId,
        environmentId: ENV,
        epoch: 1,
        dek: makeDek(),
        recipientUserId: STRANGER,
        recipientEncPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
        signerUserId: OWNER,
      }),
    ];
    const response = await createEnvironmentWith(fixture, ENV, "App", deks);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-not-member");
  });

  it("rejects a wrap under a key that differs from the chain (422 recipient-key-mismatch)", async () => {
    const good = await wrapsFor(ENV, [OWNER, MEMBER]);
    const badKey = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: makeDek(),
      recipientUserId: READER,
      // Wrapped to MEMBER's key instead of READER's on-chain key (equivalent to a ghost member)
      recipientEncPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
      signerUserId: OWNER,
    });
    const response = await createEnvironmentWith(fixture, ENV, "App", [...good, badKey]);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-key-mismatch");
  });

  it("rejects duplicate recipients and out-of-range epochs", async () => {
    const base = await wrapsFor(ENV, ALL_MEMBERS);
    const duplicated = [...base, ...(await wrapsFor(ENV, [OWNER]))];
    const dupResponse = await createEnvironmentWith(fixture, ENV, "App", duplicated);
    expect(dupResponse.status).toBe(422);
    expect(((await dupResponse.json()) as { reason: string }).reason).toBe("duplicate-recipient");

    // The current epoch at environment creation is always 1 (§12-4). Epoch 2 is out of range
    const epoch2 = await wrapsFor(ENV, ALL_MEMBERS, 2);
    const epochResponse = await createEnvironmentWith(fixture, ENV, "App", epoch2);
    expect(epochResponse.status).toBe(422);
    expect(((await epochResponse.json()) as { reason: string }).reason).toBe("epoch-out-of-range");
  });
});
