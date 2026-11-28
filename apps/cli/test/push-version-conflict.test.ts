import {
  decryptValue,
  distributedValue,
  headOf,
  valueSignedBytesHashOf,
  type WireEncryptedPayload,
} from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import {
  chainSequenceHandlerOf,
  chainV1,
  chainV2,
  type CreateBody,
  type CreateEcho,
  dek1,
  dek2,
  dekSequenceHandlerOf,
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
import { MockServer, offSpec, onEndpoint } from "./support/server.ts";

describe("maruhi push", () => {
  it("VersionConflict (409) verifies the refetched winner and retries with prev re-pointed to its hash", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await distributedValue({
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
    const winner = await distributedValue({
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
      chainSequenceHandlerOf([chainV1]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf(
              [{ ...entryExisting, value: pullCalls === 1 ? existing : winner }],
              [wrap1],
            ),
          };
        },
      ),
      onEndpoint(
        "variables.push",
        { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-existing" },
        (request) => {
          const body = request.body as { value: WireEncryptedPayload };
          pushBodies.push(body.value);
          if (pushBodies.length === 1) {
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
    expect(pushBodies[0]?.prevValueSigHashHex).toBe(
      await valueSignedBytesHashOf(existing, owner.userId),
    );
    expect(pushBodies[1]?.prevValueSigHashHex).toBe(
      await valueSignedBytesHashOf(winner, owner.userId),
    );
    expect(pushBodies[0]?.nonceHex).not.toBe(pushBodies[1]?.nonceHex);
    expect(await decryptValue(dek1, pushBodies[1] as WireEncryptedPayload)).toBe("new-value");
    expect(
      server.requests.filter(
        (request) =>
          request.method === "GET" &&
          request.path === `/projects/${chainV1.projectId}/environments/${ENV_ID}/deks`,
      ),
    ).toHaveLength(0);
  });

  it("refuses when the 409's claim is older than the verified latest (a rollback)", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const v4 = await distributedValue({
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
    const rolledBack = await distributedValue({
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
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf(
              [{ ...entryExisting, value: pullCalls === 1 ? v4 : rolledBack }],
              [wrap1],
            ),
          };
        },
      ),
      onEndpoint(
        "variables.push",
        { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-existing" },
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
    expect(env.errors.join("\n")).toContain("rollback");
  });

  it("refuses when the post-409 winner's prev does not chain to the verified previous version", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const v4 = await distributedValue({
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
    const forkedV5 = await distributedValue({
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
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf(
              [{ ...entryExisting, value: pullCalls === 1 ? v4 : forkedV5 }],
              [wrap1],
            ),
          };
        },
      ),
      onEndpoint(
        "variables.push",
        { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-existing" },
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
    const head3 = headOf(chainV2, 3);
    const head2 = headOf(chainV2, 2);
    const knownV4 = await distributedValue({
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
    const regressedV6 = await distributedValue({
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
      chainSequenceHandlerOf([chainV2]),
      dekSequenceHandlerOf([[wrap1, wrap2]]),
      pullMetadataHandlerOf([[entryExisting.statement]], 2),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf(
              [{ ...entryExisting, value: pullCalls === 1 ? knownV4 : regressedV6 }],
              [wrap1, wrap2],
              2,
            ),
          };
        },
      ),
      onEndpoint(
        "variables.push",
        { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-existing" },
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
    const existing = await distributedValue({
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
        chainSequenceHandlerOf([chainV1]),
        dekSequenceHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[entryExisting.statement]]),
        pullHandlerOf([entryExisting], [wrap1]),
        onEndpoint(
          "variables.push",
          { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-existing" },
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
    const existing = await distributedValue({
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
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf(pullCalls === 1 ? [entryExisting] : [], [wrap1]),
          };
        },
      ),
      onEndpoint(
        "variables.push",
        { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-existing" },
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
    const existing = await distributedValue({ ...coordinates, plaintext: "old" });
    const forked = await distributedValue({ ...coordinates, plaintext: "forked" });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf(
              [{ ...entryExisting, value: pullCalls === 1 ? existing : forked }],
              [wrap1],
            ),
          };
        },
      ),
      onEndpoint(
        "variables.push",
        { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-existing" },
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
    expect(chainV2.projectId).toBe(chainV1.projectId);
    const createBodies: CreateBody[] = [];
    const echo: CreateEcho = { body: null, baseVariant: [] };
    const server = await MockServer.start([
      chainSequenceHandlerOf([chainV1, chainV2]),
      dekSequenceHandlerOf([[wrap1], [wrap1, wrap2]]),
      pullMetadataHandlerOf([[]], 1, echo),
      onEndpoint(
        "variables.create",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        (request) => {
          const body = request.body as CreateBody;
          createBodies.push(body);
          if (createBodies.length === 1) {
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
    expect(createBodies[1]?.value.aad.epoch).toBe(2);
    expect(await decryptValue(dek2, (createBodies[1] as CreateBody).value)).toBe("rotated-value");
    expect(
      server.requests.filter((r) => r.path === `/projects/${chainV1.projectId}/chain`),
    ).toHaveLength(2);
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("rotated-value");
  });

  it("an EpochConflict claim contradicting the chain (current epoch unchanged after resync) is reported as a contradiction regardless of attempt count", async () => {
    const env = await startEnv(
      [
        chainSequenceHandlerOf([chainV1]),
        dekSequenceHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[]]),
        onEndpoint(
          "variables.create",
          { projectId: chainV1.projectId, environmentId: ENV_ID },
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
        chainSequenceHandlerOf([chainV1, chainV2]),
        dekSequenceHandlerOf([[wrap1], [wrap1]]),
        pullMetadataHandlerOf([[]]),
        onEndpoint(
          "variables.create",
          { projectId: chainV1.projectId, environmentId: ENV_ID },
          () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 2 } }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No DEK for the current epoch 2 is registered for you");
  });

  it("a create conflict (concurrent creation) re-resolves by name and switches to the push path", async () => {
    const existing = await distributedValue({
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
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[], [entryRacer.statement]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf([entryRacer], [wrap1], 1, 2, await manifestHashAt([])),
          };
        },
      ),
      onEndpoint(
        "variables.create",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        () => ({
          status: 409,
          json: { _tag: "VariableConflict", variableId: "ignored", reason: "duplicate-name" },
        }),
      ),
      onEndpoint(
        "variables.push",
        { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-racer" },
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
    expect(pullCalls).toBe(1);
    const body = pushed as WireEncryptedPayload | null;
    expect(body?.aad.variableId).toBe("v-racer");
    expect(body?.aad.version).toBe(2);
    expect(body?.prevValueSigHashHex).toBe(await valueSignedBytesHashOf(existing, owner.userId));
  });

  it("a raw out-of-schema 413 is reported as 'the value is too large'", async () => {
    const env = await startEnv(
      [
        chainSequenceHandlerOf([chainV1]),
        dekSequenceHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[]]),
        onEndpoint(
          "variables.create",
          { projectId: chainV1.projectId, environmentId: ENV_ID },
          () => offSpec({ status: 413, bodyText: "Payload Too Large" }),
        ),
      ],
      "big-value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("HTTP 413");
    expect(env.errors.join("\n")).toContain("too large");
  });

  it("a VersionConflict on the create path (an anomalous response) also re-resolves by name and does not self-destruct", async () => {
    const existing = await distributedValue({
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
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[], [entryLate.statement]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf([entryLate], [wrap1], 1, 2, await manifestHashAt([])),
          };
        },
      ),
      onEndpoint(
        "variables.create",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        () => ({
          status: 409,
          json: { _tag: "VersionConflict", currentVersion: 1 },
        }),
      ),
      onEndpoint(
        "variables.push",
        { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-late" },
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
    expect(pullCalls).toBe(1);
    expect(pushedVersion).toBe(2);
  });

  it("refuses when name resolution finds duplicate variable names (never binds to an arbitrary one)", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await distributedValue({
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
    const other = await distributedValue({
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
        chainSequenceHandlerOf([chainV1]),
        dekSequenceHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[entryA.statement, entryB.statement]]),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Multiple live statements with the same name");
  });
});
