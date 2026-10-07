// Tests for push (§12-5 CAS): create / new version, 409 retries
// (VersionConflict / EpochConflict = resync → re-encrypt → retry),
// and the raw out-of-schema 413 branch.

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  decryptWire,
  encryptValueFor,
  headOf,
  valueHashOf,
  type WireEncryptedPayload,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import {
  chainHandlerOf,
  chainV1,
  chainV2,
  type CreateBody,
  type CreateEcho,
  dek1,
  dek2,
  deksHandlerOf,
  entryOf,
  ENV_ID,
  manifestHashAt,
  owner,
  pullHandlerOf,
  pullJsonOf,
  pullMetadataHandlerOf,
  servers,
  startEnv,
  wrap1,
  wrap2,
} from "./support/push.ts";
import { MockServer, onRequest } from "./support/server.ts";

describe("maruhi push", () => {
  it("VersionConflict (409) verifies the refetched winner and retries with prev re-pointed to its hash", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "old",
      writer: owner,
      head,
    });
    // The actual winner version 7 (visible on the refetch after the 409)
    const winner = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 7,
      plaintext: "winner",
      writer: owner,
      head,
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    const pushBodies: WireEncryptedPayload[] = [];
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      // No listMine handler placed: a push to an existing variable uses the DEK
      // bundled in the value-bearing pull and never double-fetches via listMine
      // (session-11 ruling 3). Calling it would 404
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? existing : winner }],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        (request) => {
          const body = request.body as { value: WireEncryptedPayload };
          pushBodies.push(body.value);
          if (pushBodies.length === 1) {
            // The conflict: someone had in fact advanced to version 7
            return { status: 409, json: { _tag: "VersionConflict", currentVersion: 7 } };
          }
          return {
            status: 200,
            json: { variableId: "v-existing", version: body.value.aad.version, epoch: 1 },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("new-value"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(pushBodies).toHaveLength(2);
    expect(pushBodies[0]?.aad.version).toBe(5);
    expect(pushBodies[1]?.aad.version).toBe(8);
    // prev points to the verified current latest → after the 409 it re-points
    // to the refetched, verified winner's signed-bytes hash (self-computed —
    // not the server-claimed hash)
    expect(pushBodies[0]?.prevValueSigHashHex).toBe(await valueHashOf(existing, owner.userId));
    expect(pushBodies[1]?.prevValueSigHashHex).toBe(await valueHashOf(winner, owner.userId));
    // The retry is re-encrypted under the new version (the nonce is new too)
    expect(pushBodies[0]?.nonceHex).not.toBe(pushBodies[1]?.nonceHex);
    expect(await decryptWire(dek1, pushBodies[1] as WireEncryptedPayload)).toBe("new-value");
    // The DEK is covered solely by what the value-bearing pull bundled; listMine is never called
    expect(
      server.requests.filter(
        (request) =>
          request.method === "GET" &&
          request.path === `/projects/${chainV1.projectId}/environments/${ENV_ID}/deks`,
      ),
    ).toHaveLength(0);
  });

  it("refuses when the 409's claim is older than the verified latest (a rollback)", async () => {
    // The client has verified v4. A malicious server returns a 409 rolled back
    // to v2, and the refetch distributes the rolled-back view (v2 = an old
    // honest value that passes every check standalone). Refuse it as a
    // regression from the verified latest (v4) held within the session
    const head = headOf(chainV1, chainV1.entries.length);
    const v4 = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "current",
      writer: owner,
      head,
    });
    const rolledBack = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 2,
      plaintext: "old-regular",
      writer: owner,
      head,
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", v4);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? v4 : rolledBack }],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    // The floor rules committed by the first pull detect it first (floor-check.ts's wording)
    expect(env.errors.join("\n")).toContain("rollback");
  });

  it("refuses when the post-409 winner's prev does not chain to the verified previous version", async () => {
    // The client has verified v4. The winner is v5, but its prev chains not to
    // v4 but to a different history (a fork) → refused by the adjacent-
    // predecessor §6.3-6 check
    const head = headOf(chainV1, chainV1.entries.length);
    const v4 = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "current",
      writer: owner,
      head,
    });
    // v5, but prev is a dummy (not v4's hash = chained to a branched history)
    const forkedV5 = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "forked",
      writer: owner,
      head,
      prevValueSigHashHex: "ab".repeat(32),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", v4);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? v4 : forkedV5 }],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 5 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "prev that does not match the verified predecessor version",
    );
  });

  it("refuses when the post-409 winner regresses the epoch across a version-number gap", async () => {
    // known = v4 at epoch 2 (verified). The winner is version 6 (a gap of 2,
    // so the adjacent prev check does not apply) but epoch 1 = regressed to
    // the old epoch (the shape of a version-number-shifting injection signed
    // under a removed member's old-epoch key). The floor's rule (a), committed
    // by the first pull, detects it first at the refetch pull (the winner
    // check remains as a defense layer for when the floor is unusable)
    const head3 = headOf(chainV2, 3); // the head that includes rotate (epoch 2 current)
    const head2 = headOf(chainV2, 2); // the head of create (epoch 1 current)
    const knownV4 = await encryptValueFor({
      dek: dek2,
      projectId: chainV2.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "v-existing",
      version: 4,
      plaintext: "current-epoch2",
      writer: owner,
      head: head3,
    });
    const regressedV6 = await encryptValueFor({
      dek: dek1,
      projectId: chainV2.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 6,
      plaintext: "regressed-epoch1",
      writer: owner,
      head: head2,
      prevValueSigHashHex: "ab".repeat(32),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", knownV4);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV2]),
      deksHandlerOf([[wrap1, wrap2]]),
      pullMetadataHandlerOf([[entryExisting.statement]], 2),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? knownV4 : regressedV6 }],
            [wrap1, wrap2],
            2,
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 6 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("monotonicity violation");
  });

  it("a refetch after 409 older than the claimed currentVersion is refused as an inconsistency", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "old",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[entryExisting.statement]]),
        // The refetch still returns version 4 (older than the 409's claimed 7)
        pullHandlerOf([entryExisting], [wrap1]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
          () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 7 } }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "older than the known latest version (7) — inconsistent",
    );
  });

  it("refuses when the winner is missing from the post-409 refetch (the floor's absence detection fires first)", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "old",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(pullCalls === 1 ? [entryExisting] : [], [wrap1]),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 7 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("omission of a verified variable");
  });

  it("refuses as equivocation when the post-409 refetch returns different signed bytes under the same version", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const coordinates = {
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      writer: owner,
      head,
    } as const;
    const existing = await encryptValueFor({ ...coordinates, plaintext: "old" });
    // A valid signature with different content at the same coordinates (version 4) — the §14.2-5 evidence shape
    const forked = await encryptValueFor({ ...coordinates, plaintext: "forked" });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? existing : forked }],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        // currentVersion 4 = a 409 claiming the same version as the verified latest
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 4 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("equivocation");
  });

  it("EpochConflict (409) resyncs → fetches the new-epoch DEK → re-encrypts and retries (the chain is the epoch's source of truth)", async () => {
    // support/push.ts assumes "two states over the same genesis" (holds via
    // Ed25519's deterministic signatures + fixed timestamps)
    expect(chainV2.projectId).toBe(chainV1.projectId);
    const createBodies: CreateBody[] = [];
    const echo: CreateEcho = { body: null, baseVariant: [] };
    const server = await MockServer.start([
      // The first sync is pre-rotation (epoch 1); the resync reveals post-rotation
      chainHandlerOf([chainV1, chainV2]),
      deksHandlerOf([[wrap1], [wrap1, wrap2]]),
      pullMetadataHandlerOf([[]], 1, echo),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request) => {
          const body = request.body as CreateBody;
          createBodies.push(body);
          if (createBodies.length === 1) {
            // The server-claimed currentEpoch is a lie (5). Pin that the source
            // of truth is the chain-derived value (2) (the regression of using
            // the claimed value would become aad.epoch=5 and be detected)
            return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 5 } };
          }
          echo.body = body;
          return {
            status: 200,
            json: {
              variableId: body.statement.variableId,
              version: 1,
              epoch: body.value.aad.epoch,
            },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("rotated-value"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(createBodies).toHaveLength(2);
    expect(createBodies[0]?.value.aad.epoch).toBe(1);
    // The retry is encrypted under the chain-derived new epoch (2 — not the
    // claimed 5) + a new DEK. The chain has been fetched twice across the resync
    expect(createBodies[1]?.value.aad.epoch).toBe(2);
    expect(await decryptWire(dek2, (createBodies[1] as CreateBody).value)).toBe("rotated-value");
    expect(
      server.requests.filter((r) => r.path === `/projects/${chainV1.projectId}/chain`),
    ).toHaveLength(2);
    // The plaintext value never appears in the output
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("rotated-value");
  });

  it("an EpochConflict claim contradicting the chain (current epoch unchanged after resync) is reported as a contradiction regardless of attempt count", async () => {
    // The server keeps returning EpochConflict every time = the attempt cap is
    // reached, but report a definite contradiction error rather than the
    // generic "the conflict does not resolve"
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[]]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
          () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 2 } }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("the server response contradicts the chain");
    expect(errors).not.toContain("did not resolve");
  });

  it("an explicit error when no new-epoch DEK addressed to self exists after an EpochConflict", async () => {
    const env = await startEnv(
      [
        chainHandlerOf([chainV1, chainV2]),
        deksHandlerOf([[wrap1], [wrap1]]),
        pullMetadataHandlerOf([[]]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
          () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 2 } }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No DEK for the current epoch 2 is registered for you");
  });

  it("a create conflict (concurrent creation) re-resolves by name and switches to the push path", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-racer",
      version: 1,
      plaintext: "raced",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryRacer = await entryOf("v-racer", "API_KEY", existing);
    let pullCalls = 0;
    let pushed: WireEncryptedPayload | null = null;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      // The first resolution sees no variable (the create path); the
      // re-resolution after the conflict sees the concurrently created
      // v-racer (resolution is a metadata-only pull — §12-7)
      pullMetadataHandlerOf([[], [entryRacer.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        // The shape where the concurrent creation's meta operation advanced
        // the manifest to v2 (the same manifest as the metadata side's
        // variant 2 — the adjacent prev chains to v1)
        return {
          status: 200,
          json: await pullJsonOf([entryRacer], [wrap1], 1, 2, await manifestHashAt([])),
        };
      }),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => ({
        status: 409,
        json: { _tag: "VariableConflict", variableId: "ignored", reason: "duplicate-name" },
      })),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-racer/versions`,
        (request) => {
          pushed = (request.body as { value: WireEncryptedPayload }).value;
          return { status: 200, json: { variableId: "v-racer", version: 2, epoch: 1 } };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("after-race"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    // The value-bearing pull runs exactly once, after the re-resolution makes
    // it an existing variable (the first resolution is metadata-only and reads no value)
    expect(pullCalls).toBe(1);
    const body = pushed as WireEncryptedPayload | null;
    expect(body?.aad.variableId).toBe("v-racer");
    expect(body?.aad.version).toBe(2);
    // After re-resolution, prev is the verified v1's (the concurrent-creation winner's) signed-bytes hash
    expect(body?.prevValueSigHashHex).toBe(await valueHashOf(existing, owner.userId));
  });

  it("a raw out-of-schema 413 is reported as 'the value is too large'", async () => {
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[]]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
          () => ({ status: 413, bodyText: "Payload Too Large" }),
        ),
      ],
      "big-value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("HTTP 413");
    expect(env.errors.join("\n")).toContain("too large");
  });

  it("a VersionConflict on the create path (an anomalous response) also re-resolves by name and does not self-destruct", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-late",
      version: 1,
      plaintext: "late",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryLate = await entryOf("v-late", "API_KEY", existing);
    let pullCalls = 0;
    let pushedVersion = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      // The first resolution sees no variable (create path); the re-resolution sees v-late
      pullMetadataHandlerOf([[], [entryLate.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        // The shape where the concurrent creation's meta operation advanced the manifest to v2 (identical to variant 2)
        return {
          status: 200,
          json: await pullJsonOf([entryLate], [wrap1], 1, 2, await manifestHashAt([])),
        };
      }),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => ({
        // A response create may return per the schema but never does in
        // practice. Never regress into falling onto the push path with the
        // random ID still in place (a push to a nonexistent ID)
        status: 409,
        json: { _tag: "VersionConflict", currentVersion: 1 },
      })),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-late/versions`,
        (request) => {
          pushedVersion = (request.body as { value: WireEncryptedPayload }).value.aad.version;
          return { status: 200, json: { variableId: "v-late", version: pushedVersion, epoch: 1 } };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    // The value-bearing pull runs only once, after re-resolution (the first resolution is metadata-only)
    expect(pullCalls).toBe(1);
    expect(pushedVersion).toBe(2);
  });

  it("refuses when name resolution finds duplicate variable names (never binds to an arbitrary one)", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-a",
      version: 1,
      plaintext: "a",
      writer: owner,
      head,
    });
    const other = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-b",
      version: 1,
      plaintext: "b",
      writer: owner,
      head,
    });
    const entryA = await entryOf("v-a", "API_KEY", existing);
    const entryB = await entryOf("v-b", "API_KEY", other);
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        // Name resolution is a metadata-only pull — a duplicate same-name active is refused by its verification
        pullMetadataHandlerOf([[entryA.statement, entryB.statement]]),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Multiple live statements with the same name");
  });
});
