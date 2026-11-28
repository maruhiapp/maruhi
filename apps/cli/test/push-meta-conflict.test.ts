import {
  distributedValue,
  distributedVariableStatement,
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
  type CreateBody,
  type CreateEcho,
  dek1,
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
} from "./support/push.ts";
import { MockServer, onEndpoint } from "./support/server.ts";

describe("maruhi push", () => {
  it("refuses when the post-409 refetched statement is a metaVersion rollback (the §12-5 meta isomorph)", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await distributedValue({
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
    const winner = await distributedValue({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "winner",
      writer: owner,
      head,
      prevValueSigHashHex: await valueSignedBytesHashOf(existing, owner.userId),
    });
    const statementV2 = await distributedVariableStatement({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 2,
    });
    const statementV1 = await distributedVariableStatement({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 1,
    });
    let pullCalls = 0;
    const server = await MockServer.start([
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[statementV2]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf(
              [
                {
                  variableId: "v-existing",
                  statement: pullCalls === 1 ? statementV2 : statementV1,
                  value: pullCalls === 1 ? existing : winner,
                },
              ],
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
    expect(env.errors.join("\n")).toContain("rollback");
  });

  it("refuses when the post-409 refetch has an adjacent metaVersion with a prev mismatch (chaining to a branched history)", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await distributedValue({
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
    const winner = await distributedValue({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "winner",
      writer: owner,
      head,
      prevValueSigHashHex: await valueSignedBytesHashOf(existing, owner.userId),
    });
    const statementV1 = await distributedVariableStatement({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 1,
    });
    const forkedSuccessor = await distributedVariableStatement({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 2,
    });
    let pullCalls = 0;
    const server = await MockServer.start([
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[statementV1]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf(
              [
                {
                  variableId: "v-existing",
                  statement: pullCalls === 1 ? statementV1 : forkedSuccessor,
                  value: pullCalls === 1 ? existing : winner,
                },
              ],
              [wrap1],
              1,
              pullCalls === 1 ? 1 : 2,
              pullCalls === 1 ? undefined : await manifestHashAt([statementV1]),
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
    expect(env.errors.join("\n")).toContain("chaining onto a diverged history");
  });

  it("refuses as equivocation when the post-409 refetch returns different signed bytes under the same metaVersion (a rename fork)", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await distributedValue({
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
    const winner = await distributedValue({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "winner",
      writer: owner,
      head,
      prevValueSigHashHex: await valueSignedBytesHashOf(existing, owner.userId),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    const forkedStatement = await distributedVariableStatement({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY_FORKED",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 1,
    });
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
              [
                pullCalls === 1
                  ? entryExisting
                  : { ...entryExisting, statement: forkedStatement, value: winner },
              ],
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
    expect(env.errors.join("\n")).toContain("equivocation");
  });

  it("a MetaVersionConflict (409) on create re-resolves by name (a conflict with a concurrent rename)", async () => {
    const existing = await distributedValue({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-meta-race",
      version: 1,
      plaintext: "raced",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryRaced = await entryOf("v-meta-race", "API_KEY", existing);
    let pullCalls = 0;
    let pushedVersion = 0;
    const server = await MockServer.start([
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[], [entryRaced.statement]]),
      onEndpoint(
        "variables.pull",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        async () => {
          pullCalls += 1;
          return {
            status: 200,
            json: await pullJsonOf([entryRaced], [wrap1], 1, 2, await manifestHashAt([])),
          };
        },
      ),
      onEndpoint(
        "variables.create",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        () => ({
          status: 409,
          json: { _tag: "MetaVersionConflict", currentMetaVersion: 1 },
        }),
      ),
      onEndpoint(
        "variables.push",
        { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-meta-race" },
        (request) => {
          pushedVersion = (request.body as { value: WireEncryptedPayload }).value.aad.version;
          return {
            status: 200,
            json: { variableId: "v-meta-race", version: pushedVersion, epoch: 1 },
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
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(pullCalls).toBe(1);
    expect(pushedVersion).toBe(2);
  });

  it("names are NFC-normalized before signing (both the lookup key and the statement — §12-1)", async () => {
    const nfdName = "CAFE\u0301_URL";
    const nfcName = nfdName.normalize("NFC");
    expect(nfcName).not.toBe(nfdName);
    const createCalls: CreateBody[] = [];
    const echo: CreateEcho = { body: null, baseVariant: [] };
    const server = await MockServer.start([
      chainSequenceHandlerOf([chainV1]),
      dekSequenceHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[]], 1, echo),
      onEndpoint(
        "variables.create",
        { projectId: chainV1.projectId, environmentId: ENV_ID },
        (request) => {
          const body = request.body as CreateBody;
          createCalls.push(body);
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
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", nfdName], env.layer)).toBe(0);
    expect(createCalls[0]?.statement.name).toBe(nfcName);
  });

  it("aborts at the attempt cap when the conflict never resolves", async () => {
    const existing = await distributedValue({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 1,
      plaintext: "old",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    let attempts = 0;
    const env = await startEnv(
      [
        chainSequenceHandlerOf([chainV1]),
        dekSequenceHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[entryExisting.statement]]),
        pullHandlerOf([entryExisting], [wrap1]),
        onEndpoint(
          "variables.push",
          { projectId: chainV1.projectId, environmentId: ENV_ID, variableId: "v-existing" },
          () => {
            attempts += 1;
            return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
          },
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(attempts).toBe(5);
    expect(env.errors.join("\n")).toContain("did not resolve");
  });

  it("refuses without aiming the push when a concurrent rename lands between name resolution and value fetch", async () => {
    const existing = await distributedValue({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "current",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    const renamedStatement = await distributedVariableStatement({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY_V2",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 2,
    });
    const env = await startEnv(
      [
        chainSequenceHandlerOf([chainV1]),
        pullMetadataHandlerOf([[entryExisting.statement]]),
        onEndpoint(
          "variables.pull",
          { projectId: chainV1.projectId, environmentId: ENV_ID },
          async () => ({
            status: 200,
            json: await pullJsonOf(
              [{ ...entryExisting, statement: renamedStatement }],
              [wrap1],
              1,
              2,
              await manifestHashAt([entryExisting.statement]),
            ),
          }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("concurrent rename");
  });

  it("refuses when the metadata-resolution response's active list mixes in a deleted statement (§12-7)", async () => {
    const deletedStatement = await distributedVariableStatement({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-dead",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 2,
      status: "deleted",
    });
    const env = await startEnv(
      [chainSequenceHandlerOf([chainV1]), pullMetadataHandlerOf([[deletedStatement]])],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("deleted statement in the live list");
  });
});
