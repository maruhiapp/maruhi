// Tests for push (§12-5 CAS): create / new version, 409 retries
// (VersionConflict / EpochConflict = resync → re-encrypt → retry),
// and the raw out-of-schema 413 branch.

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  encryptValueFor,
  headOf,
  statementFor,
  valueHashOf,
  type WireEncryptedPayload,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import {
  chainHandlerOf,
  chainV1,
  type CreateBody,
  type CreateEcho,
  dek1,
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
} from "./support/push.ts";
import { MockServer, onRequest } from "./support/server.ts";

describe("maruhi push", () => {
  it("refuses when the post-409 refetched statement is a metaVersion rollback (the §12-5 meta isomorph)", async () => {
    // The client has verified the metaVersion-2 statement. The refetch (post-
    // 409) distributing a metaVersion-1 statement = evidence of a metadata rollback
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
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
    const winner = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "winner",
      writer: owner,
      head,
      prevValueSigHashHex: await valueHashOf(existing, owner.userId),
    });
    const statementV2 = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 2,
    });
    const statementV1 = await statementFor({
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
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[statementV2]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
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
    // The floor's rule (a), committed by the first pull, detects it first (floor-check.ts's wording)
    expect(env.errors.join("\n")).toContain("rollback");
  });

  it("refuses when the post-409 refetch has an adjacent metaVersion with a prev mismatch (chaining to a branched history)", async () => {
    // The client has verified the metaVersion-1 statement. The refetched (post-
    // 409) metaVersion-2's prev not matching the verified signed-bytes hash =
    // refuse to follow a branched prev chain (isomorphic to
    // winnerValueRegression's adjacency check)
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
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
    const winner = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "winner",
      writer: owner,
      head,
      prevValueSigHashHex: await valueHashOf(existing, owner.userId),
    });
    const statementV1 = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 1,
    });
    // prev's default ("cd"×32) does not match statementV1's signed-bytes hash
    const forkedSuccessor = await statementFor({
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
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[statementV1]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
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
            // The second time, the metaVersion-2 winner = the manifest also
            // advances by one meta operation (an adjacent version, so prev
            // chains to the v1 manifest — independent of the manifest's own
            // prev verification, only the winner statement's prev mismatch is pinned)
            pullCalls === 1 ? 1 : 2,
            pullCalls === 1 ? undefined : await manifestHashAt([statementV1]),
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
    expect(env.errors.join("\n")).toContain("chaining onto a diverged history");
  });

  it("refuses as equivocation when the post-409 refetch returns different signed bytes under the same metaVersion (a rename fork)", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
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
    const winner = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "winner",
      writer: owner,
      head,
      prevValueSigHashHex: await valueHashOf(existing, owner.userId),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    // Valid statements under the same metaVersion (1) with differing name = evidence of a rename fork
    const forkedStatement = await statementFor({
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
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
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
    expect(env.errors.join("\n")).toContain("equivocation");
  });

  it("a MetaVersionConflict (409) on create re-resolves by name (a conflict with a concurrent rename)", async () => {
    const existing = await encryptValueFor({
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
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      // The first resolution sees no variable (create path); the re-resolution sees v-meta-race
      pullMetadataHandlerOf([[], [entryRaced.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        // The shape where the concurrent rename's meta operation advanced the manifest to v2 (identical to variant 2)
        return {
          status: 200,
          json: await pullJsonOf([entryRaced], [wrap1], 1, 2, await manifestHashAt([])),
        };
      }),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => ({
        status: 409,
        json: { _tag: "MetaVersionConflict", currentMetaVersion: 1 },
      })),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-meta-race/versions`,
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
    // The value-bearing pull runs only once, after re-resolution (the first resolution is metadata-only)
    expect(pullCalls).toBe(1);
    expect(pushedVersion).toBe(2);
  });

  it("names are NFC-normalized before signing (both the lookup key and the statement — §12-1)", async () => {
    // Push with an NFD (combining-character) name → the bundled statement's name is the NFC normal form
    const nfdName = "CAFE\u0301_URL";
    const nfcName = nfdName.normalize("NFC");
    expect(nfcName).not.toBe(nfdName);
    const createCalls: CreateBody[] = [];
    const echo: CreateEcho = { body: null, baseVariant: [] };
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[]], 1, echo),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
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
    // The server keeps returning "the same currentVersion as the verified
    // latest + a distribution of the same value" = each round's winner checks
    // (absence · stale pull · equivocation) pass but nothing advances. Cut off at the generic attempt cap
    const existing = await encryptValueFor({
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
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[entryExisting.statement]]),
        pullHandlerOf([entryExisting], [wrap1]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
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
    // Metadata resolution: API_KEY → v-existing. The value-bearing pull sees
    // the same variable already renamed to API_KEY_V2 (metaVersion 2) = blocks
    // a push aimed at a variable whose name changed from the typed one
    const existing = await encryptValueFor({
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
    const renamedStatement = await statementFor({
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
        chainHandlerOf([chainV1]),
        pullMetadataHandlerOf([[entryExisting.statement]]),
        // The concurrent rename's meta operation also advances the manifest to
        // v2 (§12-5 — a same-version set difference would be equivocation, so
        // it is assembled in the shape of an honest rename)
        onRequest(
          "GET",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`,
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
    // A metadata-only pull is under the same verification discipline as a
    // value-bearing one (the carriage form of unauthorized deletion reversal.
    // With no values, verification completes on the statement side alone)
    const deletedStatement = await statementFor({
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
      [chainHandlerOf([chainV1]), pullMetadataHandlerOf([[deletedStatement]])],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("deleted statement in the live list");
  });
});
