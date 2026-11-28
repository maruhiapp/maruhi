import {
  decryptValue,
  distributedVariablesDigestOf,
  distributedVariableStatement,
  headOf,
  testProjectId,
} from "@maruhi/test-kit";
import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import {
  chainHandlerOf,
  chainV1,
  type CreateBody,
  type CreateEcho,
  dek1,
  deksHandlerOf,
  distributedStatementOf,
  ENV_ID,
  envStatement,
  manifestHashAt,
  manifestOf,
  owner,
  pullMetadataHandlerOf,
  servers,
  wrap1,
} from "./support/push.ts";
import { type MockRequest, MockServer, onRequest } from "./support/server.ts";

describe("maruhi push", () => {
  it("a new variable is a create (version 1); the stdin value is encrypted under the current epoch", async () => {
    const createCalls: CreateBody[] = [];
    const echo: CreateEcho = { body: null, baseVariant: [] };
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[]], 1, echo),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request: MockRequest) => {
          const body = request.body as CreateBody;
          createCalls.push(body);
          echo.body = body;
          return {
            status: 200,
            json: {
              variableId: body.statement.variableId,
              version: body.value.aad.version,
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
    env.setStdin(new TextEncoder().encode("secret-value\n"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(createCalls).toHaveLength(1);
    const body = createCalls[0] as CreateBody;
    expect(body.statement.name).toBe("API_KEY");
    expect(body.statement.status).toBe("active");
    expect(body.statement.metaVersion).toBe(1);
    expect(body.statement.prevMetaSigHashHex).toBe("");
    expect(body.statement.chainHeadSeq).toBe(chainV1.entries.length);
    expect(body.statement.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    expect(body.value.aad).toEqual({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: body.statement.variableId,
      version: 1,
    });
    expect(body.value.prevValueSigHashHex).toBe("");
    expect(body.value.chainHeadSeq).toBe(chainV1.entries.length);
    expect(body.value.chainHeadHashHex).toBe(headOf(chainV1, chainV1.entries.length).hashHex);
    expect(body.value.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    expect(await decryptValue(dek1, body.value)).toBe("secret-value");
    expect(body.manifest.manifestVersion).toBe(2);
    expect(body.manifest.prevManifestSigHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(body.manifest.epoch).toBe(1);
    expect(body.manifest.chainHeadSeq).toBe(chainV1.entries.length);
    expect(body.manifest.variablesDigestHex).toBe(
      await distributedVariablesDigestOf(chainV1.projectId, [
        { ...body.statement, authorUserId: owner.userId },
      ]),
    );
    expect(body.manifest.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    expect(env.logs.join("\n")).toContain("version=1");
    const paths = server.requests.map((request) => request.path);
    expect(paths).toContain(`/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`);
    expect(paths).not.toContain(`/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`);
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(testProjectId(chainV1.projectId)),
    );
    const record = loaded.floor?.environments[ENV_ID];
    expect(record?.variables[body.statement.variableId]).toMatchObject({
      status: "active",
      version: 1,
      epoch: 1,
      metaVersion: 1,
    });
    expect(record?.manifest?.manifestVersion).toBe(2);
    expect(loaded.floor?.intents).toEqual([]);
  });

  it("when the post-acceptance server echo disagrees with the locally signed value, it is reported as a typed error", async () => {
    const echo: CreateEcho = { body: null, baseVariant: [] };
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[]], 1, echo),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request: MockRequest) => {
          const body = request.body as CreateBody;
          echo.body = body;
          return {
            status: 200,
            json: {
              variableId: body.statement.variableId,
              version: 999,
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
    env.setStdin(new TextEncoder().encode("secret-value\n"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("echoes different coordinates");
    const created = echo.body as CreateBody | null;
    expect(created).not.toBeNull();
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(testProjectId(chainV1.projectId)),
    );
    expect(
      loaded.floor?.environments[ENV_ID]?.variables[created?.statement.variableId ?? ""],
    ).toMatchObject({ status: "active", version: 1, epoch: 1 });
  });

  it("if appending the intent (3-F) fails, never send the variable creation (fail-closed journal-before-send)", async () => {
    let createCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[]]),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => {
        createCalls += 1;
        return { status: 200, json: { variableId: "vx", version: 1, epoch: 1 } };
      }),
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
    env.failFloorIntentAppends();

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(createCalls).toBe(0);
    expect(env.errors.join("\n")).toContain("intent");
  });

  it("with an old-server equivalent (silently drops the manifest and returns 200), the post-acceptance check fails and the floor's manifest does not advance (1-E′ — §12-10 (3))", async () => {
    let created: CreateBody | null = null;
    let metadataCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      onRequest(
        "GET",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`,
        async () => {
          metadataCalls += 1;
          return {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch: 1,
              statement: envStatement,
              variables: created === null ? [] : [distributedStatementOf(created)],
              deletedVariables: [],
              manifest: await manifestOf([], 1, 1),
              schemaPolicy: "enabled" as const,
            },
          };
        },
      ),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request) => {
          created = request.body as CreateBody;
          return {
            status: 200,
            json: {
              variableId: (request.body as CreateBody).statement.variableId,
              version: 1,
              epoch: 1,
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

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("post-acceptance confirmation");
    expect(errors).toContain("success is defined by the confirmed effect");
    expect(metadataCalls).toBeGreaterThanOrEqual(2);
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(testProjectId(chainV1.projectId)),
    );
    const record = loaded.floor?.environments[ENV_ID];
    expect(record?.manifest?.manifestVersion).toBe(1);
    const body = created as CreateBody | null;
    expect(record?.variables[body?.statement.variableId ?? ""]).toBeUndefined();
    expect(loaded.floor?.intents).toHaveLength(1);
  });

  it("a different manifest distributed under the same version fails as a hash mismatch (1-E′ — §12-10 (3))", async () => {
    const extraStatement = await distributedVariableStatement({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-injected",
      name: "INJECTED",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
    });
    let created: CreateBody | null = null;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      onRequest(
        "GET",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`,
        async () => {
          if (created === null) {
            return {
              status: 200,
              json: {
                environmentId: ENV_ID,
                currentEpoch: 1,
                statement: envStatement,
                variables: [],
                deletedVariables: [],
                manifest: await manifestOf([], 1, 1),
                schemaPolicy: "enabled" as const,
              },
            };
          }
          const statements = [distributedStatementOf(created), extraStatement];
          return {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch: 1,
              statement: envStatement,
              variables: statements,
              deletedVariables: [],
              manifest: await manifestOf(statements, 1, 2, await manifestHashAt([])),
              schemaPolicy: "enabled" as const,
            },
          };
        },
      ),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request) => {
          created = request.body as CreateBody;
          return {
            status: 200,
            json: {
              variableId: (request.body as CreateBody).statement.variableId,
              version: 1,
              epoch: 1,
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

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("distributes a different manifest at the issued manifestVersion");
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(testProjectId(chainV1.projectId)),
    );
    expect(loaded.floor?.intents).toEqual([]);
    expect(loaded.floor?.environments[ENV_ID]?.manifest?.manifestVersion).toBe(2);
  });
});
