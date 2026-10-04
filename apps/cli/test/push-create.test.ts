// Tests for push (§12-5 CAS): create / new version, 409 retries
// (VersionConflict / EpochConflict = resync → re-encrypt → retry),
// and the raw out-of-schema 413 branch.

import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import { headOf, statementFor, variablesDigestOf } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import {
  chainHandlerOf,
  chainV1,
  type CreateBody,
  type CreateEcho,
  decryptWire,
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
          // Accepted: later metadata pulls (the confirmation — §12-10 (3)) distribute it
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
    // The creation bundles a metaVersion-1 statement (§12-5): signed by author,
    // empty prev, declared head = the last verified chain head
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
    // The value-signature block (§4.1): a new variable has empty prev, declared
    // head = the last verified chain head, writer = self (the signature is the master sig key)
    expect(body.value.prevValueSigHashHex).toBe("");
    expect(body.value.chainHeadSeq).toBe(chainV1.entries.length);
    expect(body.value.chainHeadHashHex).toBe(headOf(chainV1, chainV1.entries.length).hashHex);
    expect(body.value.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    // One trailing newline is stripped, and the value decrypts under the current-epoch DEK
    expect(await decryptWire(dek1, body.value)).toBe("secret-value");
    // The bundled manifest (§12-4): next of the previous (server-distributed
    // v1) = v2; prev is the verified previous manifest's signed-bytes hash;
    // the digest is recomputed from the post-creation full variable set (= the 1 new statement)
    expect(body.manifest.manifestVersion).toBe(2);
    expect(body.manifest.prevManifestSigHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(body.manifest.epoch).toBe(1);
    expect(body.manifest.chainHeadSeq).toBe(chainV1.entries.length);
    expect(body.manifest.variablesDigestHex).toBe(
      await variablesDigestOf(chainV1.projectId, [
        { ...body.statement, authorUserId: owner.userId },
      ]),
    );
    expect(body.manifest.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    expect(env.logs.join("\n")).toContain("version=1");
    // Name resolution for a new creation uses a metadata-only pull (§12-7) and
    // never calls a value-bearing pull = a path where the server records no
    // var.read (session-11 ruling 3)
    const paths = server.requests.map((request) => request.path);
    expect(paths).toContain(`/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`);
    expect(paths).not.toContain(`/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`);
    // The positive side pinned (the negative side — "never write unconfirmed" —
    // is pinned by the old-server test): a creation that **passed** the
    // confirmation (1-E′) promotes its own write into the floor; the
    // confirmation pull's verified manifest (= self-issued v2) is in the floor, and the intent closes
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(chainV1.projectId),
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
          // Accepts, but makes the echo's version disagree with the locally signed value (1)
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
    // Promotion into the floor has completed with the locally signed value (the echo comparison runs after the floor commit)
    const created = echo.body as CreateBody | null;
    expect(created).not.toBeNull();
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(chainV1.projectId),
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
    // Never fire a security-critical mutation without recording the confirmation obligation
    expect(createCalls).toBe(0);
    expect(env.errors.join("\n")).toContain("intent");
  });

  it("with an old-server equivalent (silently drops the manifest and returns 200), the post-acceptance check fails and the floor's manifest does not advance (1-E′ — §12-10 (3))", async () => {
    // The shape of an old server without strict acceptance (§12-10 (1)): it
    // returns 200 for the variable creation but never stores the bundled
    // manifest, and keeps distributing the old manifest (v1, the pre-creation
    // set). Because success is defined as confirmation over verifiable
    // distributed artifacts, the CLI does not call it success and does not
    // write its self-issued manifest to the floor (the post-acceptance check)
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
              // After acceptance the statement is stored (values / meta are
              // stored even by an old server), but the manifest stays v1 (the
              // pre-creation empty set) = the shape of silent dropping
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
    // Reported as a confirmation failure (a 2xx must not be read as success)
    expect(errors).toContain("post-acceptance confirmation");
    expect(errors).toContain("success is defined by the confirmed effect");
    // The confirmation metadata pull did actually run (the post-acceptance check)
    expect(metadataCalls).toBeGreaterThanOrEqual(2);
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(chainV1.projectId),
    );
    const record = loaded.floor?.environments[ENV_ID];
    // The self-issued manifest (v2) is not written to the floor — only verified
    // observations (the resolution pull's v1) are recorded. Do not pin "a
    // manifest the old server never stored" into the floor and create the accident
    // where every later absence is misjudged as an omission
    expect(record?.manifest?.manifestVersion).toBe(1);
    // **The variable floor is not written either** (§12-10 (3) — floor records
    // only after the confirmation passes). Planting your own write into the
    // floor on the basis of a 2xx alone would make every later pull
    // permanently refuse with variable-omitted if the server never actually
    // stored it (an unconfirmed belief morphs into equivocation evidence)
    const body = created as CreateBody | null;
    expect(record?.variables[body?.statement.variableId ?? ""]).toBeUndefined();
    // The confirmation-obligation record (the intent — 3-F) stays unresolved
    expect(loaded.floor?.intents).toHaveLength(1);
  });

  it("a different manifest distributed under the same version fails as a hash mismatch (1-E′ — §12-10 (3))", async () => {
    // The server returns 200 but distributes a verifiable manifest of
    // **different content** under the issued manifestVersion (covering your
    // variable + an injected one). The digest is consistent with the
    // distributed set, so the §4.3 verification passes — only the comparison
    // against the self-issued (version, hash) detects this
    const extraStatement = await statementFor({
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
              // Same manifestVersion (2) but covering a different set =
              // different signed bytes. prev chains correctly to v1 (a shape
              // that passes the adjacent prev check — to pin the hash comparison)
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
      makeFileFloorStore(env.floorDir).load(chainV1.projectId),
    );
    // Confirmed that the issued manifest was not stored = the intent closes as
    // not-accepted (the verified distributed-side v2' remains in the floor as an observation)
    expect(loaded.floor?.intents).toEqual([]);
    expect(loaded.floor?.environments[ENV_ID]?.manifest?.manifestVersion).toBe(2);
  });
});
