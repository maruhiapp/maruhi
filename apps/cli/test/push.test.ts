// Tests for push (§12-5 CAS): create / new version, 409 retries
// (VersionConflict / EpochConflict = resync → re-encrypt → retry),
// and the raw out-of-schema 413 branch.

import { decryptVariable } from "@maruhi/crypto";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  rotateEpochOp,
  statementFor,
  variablesDigestOf,
  type TestUser,
  valueHashOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
  type WireEncryptedPayload,
  wrapDekFor,
  type WireRecipientDek,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";

let owner: TestUser;
let chainV1: BuiltChain;
let chainV2: BuiltChain;
let dek1: Uint8Array;
let dek2: Uint8Array;
let wrap1: WireRecipientDek;
let wrap2: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

/** One variable of a pull response (verified statement + value). The declared head is genesis. */
async function entryOf(
  variableId: string,
  name: string,
  value: WireEncryptedPayload,
): Promise<{
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireEncryptedPayload;
}> {
  return {
    variableId,
    statement: await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId,
      name,
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
    }),
    value,
  };
}

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  chainV1 = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  // The shape where a rotation is stacked on the same genesis (same project)
  chainV2 = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  const common = { projectId: chainV1.projectId, environmentId: ENV_ID };
  wrap1 = await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner });
  wrap2 = await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner });
  envStatement = await environmentStatementFor({
    projectId: chainV1.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: chainV1.projectId },
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandlerOf(chains: readonly BuiltChain[]): MockHandler {
  // Advances on each call (the EpochConflict resync reveals the new chain). Stops at the last one
  let call = 0;
  return onRequest("GET", `/projects/${chainV1.projectId}/chain`, () => {
    const built = chains[Math.min(call, chains.length - 1)] as BuiltChain;
    call += 1;
    return {
      status: 200,
      json: {
        projectId: chainV1.projectId,
        entries: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
      },
    };
  });
}

function deksHandlerOf(sets: readonly (readonly WireRecipientDek[])[]): MockHandler {
  let call = 0;
  return onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/deks`, () => {
    const deks = sets[Math.min(call, sets.length - 1)] ?? [];
    call += 1;
    return { status: 200, json: { deks } };
  });
}

/**
 * The manifest computed from the distributed set itself (§12-7). Ed25519 is
 * deterministic, so recomputing the same set matches byte-exactly (no equivocation).
 */
async function manifestOf(
  statements: readonly WireDistributedVariableStatement[],
  currentEpoch = 1,
  manifestVersion = 1,
  prevManifestSigHashHex?: string,
): Promise<unknown> {
  return manifestFor({
    projectId: chainV1.projectId,
    environmentId: ENV_ID,
    epoch: currentEpoch,
    issuer: owner,
    head: currentEpoch === 1 ? headOf(chainV1, 2) : headOf(chainV2, 3),
    envStatement,
    statements,
    manifestVersion,
    ...(prevManifestSigHashHex === undefined ? {} : { prevManifestSigHashHex }),
  });
}

/** The response JSON of a value-bearing pull (§12-7) — manifest bundled. */
async function pullJsonOf(
  variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireEncryptedPayload;
  }[],
  deks: readonly WireRecipientDek[],
  currentEpoch = 1,
  /** A response whose meta set changes takes the next version (a same-version set difference is equivocation). */
  manifestVersion = 1,
  /** prev for version > 1 (the previous manifest's hash — the chain for the adjacent prev check). */
  prevManifestSigHashHex?: string,
): Promise<unknown> {
  return {
    environmentId: ENV_ID,
    currentEpoch,
    statement: envStatement,
    variables,
    deletedVariables: [],
    deks,
    manifest: await manifestOf(
      variables.map((variable) => variable.statement),
      currentEpoch,
      manifestVersion,
      prevManifestSigHashHex,
    ),
  };
}

/** The signed-bytes hash of the manifest for a given set · version (material for the next version's prev). */
async function manifestHashAt(
  statements: readonly WireDistributedVariableStatement[],
  currentEpoch = 1,
  manifestVersion = 1,
  prevManifestSigHashHex?: string,
): Promise<string> {
  return manifestHashOf(
    chainV1.projectId,
    (await manifestOf(
      statements,
      currentEpoch,
      manifestVersion,
      prevManifestSigHashHex,
    )) as WireDistributedManifest,
  );
}

function pullHandlerOf(
  variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireEncryptedPayload;
  }[],
  deks: readonly WireRecipientDek[],
): MockHandler {
  return onRequest(
    "GET",
    `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`,
    async () => ({
      status: 200,
      json: await pullJsonOf(variables, deks),
    }),
  );
}

/**
 * The box that records variable-creation acceptances (shared state so the
 * §12-10 (3) confirmation pull can mimic distributing the accepted statement + manifest).
 */
interface CreateEcho {
  body: CreateBody | null;
  /** The variant that became the creation's issueBase (distributed set = variant + creation statement). */
  baseVariant: readonly WireDistributedVariableStatement[];
}

/** Issued form → distributed form (§12-2 — the server attaches the caller's attribution). */
function distributedStatementOf(body: CreateBody): WireDistributedVariableStatement {
  return {
    ...body.statement,
    authorUserId: owner.userId,
    authorKeyFingerprintHex: owner.fingerprintHex,
  } as WireDistributedVariableStatement;
}

/**
 * The response of a metadata-only pull (§12-7). Advances through variants on
 * each call (stops at the last). Manifests between variants actually chain
 * their prev (models a legitimate "another member's meta operation" that
 * satisfies the adjacent-version prev check).
 * When `echo` holds an accepted creation, it returns that distribution
 * (variant + creation statement + accepted manifest) — material for the confirmation (§12-10 (3)).
 */
function pullMetadataHandlerOf(
  variants: readonly (readonly WireDistributedVariableStatement[])[],
  currentEpoch = 1,
  echo?: CreateEcho,
): MockHandler {
  let call = 0;
  const manifests: WireDistributedManifest[] = [];
  const manifestAt = async (index: number): Promise<WireDistributedManifest> => {
    for (let position = manifests.length; position <= index; position += 1) {
      const previous = manifests[position - 1];
      manifests[position] = (await manifestOf(
        variants[position] ?? [],
        currentEpoch,
        position + 1,
        previous === undefined ? undefined : await manifestHashOf(chainV1.projectId, previous),
      )) as WireDistributedManifest;
    }
    return manifests[index] as WireDistributedManifest;
  };
  return onRequest(
    "GET",
    `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`,
    async () => {
      if (echo !== undefined && echo.body !== null) {
        // Accepted: the distributed form = the issueBase set + creation
        // statement; the manifest = the accepted issued form + issuer
        // attribution (isomorphic to acceptRotate in env-rotate.test.ts)
        return {
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch,
            statement: envStatement,
            variables: [...echo.baseVariant, distributedStatementOf(echo.body)],
            deletedVariables: [],
            manifest: {
              ...echo.body.manifest,
              issuerUserId: owner.userId,
              issuerKeyFingerprintHex: owner.fingerprintHex,
            },
          },
        };
      }
      const index = Math.min(call, variants.length - 1);
      const variables = variants[index] ?? [];
      call += 1;
      return {
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch,
          statement: envStatement,
          variables,
          deletedVariables: [],
          // A variant advance = one meta operation by another member, modeled.
          // manifestVersion advances with it (consistent with the floor's monotonicity)
          manifest: await manifestAt(index),
        },
      };
    },
  );
}

async function startEnv(handlers: readonly MockHandler[], stdin: string): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: chainV1.projectId,
    defaultEnvironment: ENV_ID,
  });
  env.setStdin(new TextEncoder().encode(stdin));
  return env;
}

interface CreateBody {
  readonly statement: WireDistributedVariableStatement;
  readonly value: WireEncryptedPayload;
  /** The bundled manifest (§12-4 — variable creation also re-issues the manifest). */
  readonly manifest: {
    readonly environmentId: string;
    readonly epoch: number;
    readonly manifestVersion: number;
    readonly variablesDigestHex: string;
    readonly envMetaVersion: number;
    readonly envMetaSigHashHex: string;
    readonly prevManifestSigHashHex: string;
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  };
}

async function decryptWire(dek: Uint8Array, value: WireEncryptedPayload): Promise<string> {
  const result = await decryptVariable({
    dek,
    context: value.aad,
    nonce: hexBytes(value.nonceHex),
    ciphertext: hexBytes(value.ciphertextHex),
  });
  if (!result.ok) {
    throw new Error("decrypt failed in test");
  }
  return new TextDecoder().decode(result.value);
}

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
    // push.test assumes "two states over the same genesis" (holds via
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
