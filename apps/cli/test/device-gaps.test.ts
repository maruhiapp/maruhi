// Integration tests for filling in missing epochs of your other devices
// (DK K11 — design note dk-design.md §16). Device ops, wraps, and
// registration signatures are real crypto; the server is a wire-level mock.
//
// Properties pinned down (K11-6):
//  1. From the bundled wrap rows, `maruhi pull` derives the missing epochs
//     of your other still-valid devices that are recipients of that
//     environment, wraps **only those epochs** to the sibling's key, and
//     registers them with this device's registration signature (the
//     registered rows open under the sibling's key and pass §5.1 signature
//     verification)
//  2. Nothing is registered when there is no gap, for legacy-server rows
//     (no `recipientEncPubHex`), or for a device that isn't a recipient
//     (outside the effective scope)
//  3. An epoch this device also cannot open is not wrapped — it is reported.
//     A registration failure stays a Note; pull still exits 0

import {
  type ChainOperation,
  decodeHex,
  importSigningPublicKey,
  SUITE_ID,
  unwrapDek,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  rotateEpochOp,
  type TestUser,
  wrapDekFor,
  type WireRecipientDek,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app";
const OTHER_ENV_ID = "env-other";

let owner: TestUser;
/** owner's second device (the sibling with a missing epoch). */
let sibling: TestUser;
/** owner's third device (its cap's scope is only OTHER_ENV_ID — not a recipient of ENV_ID). */
let narrow: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;
let built: BuiltChain;

const servers: MockServer[] = [];

function addDeviceOp(device: TestUser, environmentIds?: readonly string[]): ChainOperation {
  return {
    op: "add_device",
    payload: {
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap: environmentIds === undefined ? "owner" : "member",
      scopeKind: environmentIds === undefined ? "all" : "listed",
      scopeEnvironmentIds: environmentIds === undefined ? [] : [...environmentIds],
    },
  };
}

beforeAll(async () => {
  owner = await makeTestUser("user-owner-0001");
  sibling = await makeTestUser("user-owner-0001");
  narrow = await makeTestUser("user-owner-0001");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    {
      actor: owner,
      operation: createEnvironmentOp(OTHER_ENV_ID, crypto.getRandomValues(new Uint8Array(32))),
    },
    { actor: owner, operation: addDeviceOp(sibling) },
    { actor: owner, operation: addDeviceOp(narrow, [OTHER_ENV_ID]) },
  ]);
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** A distribution row destined to a device key (the new-server shape — carries `recipientEncPubHex`). */
async function rowFor(
  device: TestUser,
  epoch: number,
  options: { readonly withRecipientKey?: boolean } = {},
): Promise<WireRecipientDek & { readonly recipientEncPubHex?: string }> {
  const wrap = await wrapDekFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    epoch,
    dek: epoch === 1 ? dek1 : dek2,
    recipient: device,
    signer: owner,
  });
  return options.withRecipientKey === false
    ? wrap
    : { ...wrap, recipientEncPubHex: device.encPubHex };
}

interface Posted {
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
}

/** Chain + a valued pull of an environment with 0 variables (swap the bundled rows) + wrap registration. */
async function start(input: {
  readonly rows: readonly unknown[];
  readonly registerStatus?: number;
}): Promise<{ env: TestEnv; posted: Posted[] }> {
  const { projectId } = built;
  const posted: Posted[] = [];
  const envStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: projectId },
  });
  const manifest = await manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: 2,
    issuer: owner,
    head: headOf(built, 3),
    envStatement,
  });
  const server = await MockServer.start([
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
      },
    })),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: 2,
        statement: envStatement,
        variables: [],
        deletedVariables: [],
        deks: input.rows,
        manifest,
      },
    })),
    onRequest("POST", `/projects/${projectId}/environments/${ENV_ID}/deks`, (request) => {
      const body = request.body as { readonly deks: readonly Posted[] };
      if (input.registerStatus !== undefined) {
        return { status: input.registerStatus, json: { _tag: "Internal" } };
      }
      posted.push(...body.deks);
      return { status: 204 };
    }),
  ]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: projectId,
    defaultEnvironment: ENV_ID,
  });
  return { env, posted };
}

describe("maruhi pull fills in the missing epochs of your other devices (DK K11)", () => {
  it("registers only the sibling's missing epochs, wrapped to the sibling's key with this device's registration signature", async () => {
    // owner holds epochs 1 and 2; sibling has only 2 (1 is missing). narrow
    // is not a recipient of ENV_ID
    const { env, posted } = await start({
      rows: [await rowFor(owner, 1), await rowFor(owner, 2), await rowFor(sibling, 2)],
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(posted.map((wrap) => [wrap.recipientEncPubHex, wrap.epoch])).toEqual([
      [sibling.encPubHex, 1],
    ]);
    const [wrap] = posted;
    if (wrap === undefined) throw new Error("no wrap");
    expect(wrap.recipientUserId).toBe(owner.userId);
    // Discriminate the destination: it opens under the sibling's key to
    // the epoch-1 DEK and the registration signature verifies
    const opened = await unwrapDek({
      recipientKeyPair: sibling.encKeyPair,
      wrapped: {
        enc: decodeHex(wrap.encHex) ?? new Uint8Array(),
        ciphertext: decodeHex(wrap.ciphertextHex) ?? new Uint8Array(),
      },
      context: {
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        recipientUserId: owner.userId,
      },
    });
    expect(opened.ok && Buffer.from(opened.value).equals(Buffer.from(dek1))).toBe(true);
    const signerKey = await importSigningPublicKey(decodeHex(owner.sigPubHex) ?? new Uint8Array());
    if (!signerKey.ok) throw new Error("signer key");
    const signature = await verifyDekWrapSignature({
      context: {
        suite: SUITE_ID,
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        recipientUserId: owner.userId,
        recipientEncPubHex: sibling.encPubHex,
        encHex: wrap.encHex,
        ciphertextHex: wrap.ciphertextHex,
        signerUserId: owner.userId,
      },
      signatureHex: wrap.signatureHex,
      signerPublicKey: signerKey.value,
    });
    expect(signature.ok).toBe(true);
    expect(env.errors.join("\n")).toContain(
      `your device ${sibling.fingerprintHex} had no keys for epoch 1 of environment ${ENV_ID} (its backfill did not complete); wrapped them to it from this device (1 registered, 0 already present)`,
    );
  });

  it("registers nothing when there is no gap, for legacy-server rows, or for a non-recipient device's gap", async () => {
    const complete = await start({
      rows: [
        await rowFor(owner, 1),
        await rowFor(owner, 2),
        await rowFor(sibling, 1),
        await rowFor(sibling, 2),
      ],
    });
    expect(await runCli(["pull"], complete.env.layer)).toBe(0);
    expect(complete.posted).toEqual([]);

    // A legacy server (rows without `recipientEncPubHex` = attribution
    // unknowable) derives nothing
    const legacy = await start({
      rows: [
        await rowFor(owner, 1, { withRecipientKey: false }),
        await rowFor(owner, 2, { withRecipientKey: false }),
      ],
    });
    expect(await runCli(["pull"], legacy.env.layer)).toBe(0);
    expect(legacy.posted).toEqual([]);
    expect(legacy.env.errors.join("\n")).not.toContain("had no keys for");
  });

  it("reports rather than wraps an epoch this device also cannot open; a registration failure stays a Note and pull is 0", async () => {
    // owner doesn't hold epoch 1 either → sibling's epoch 1 can't be filled
    // (not wrapped)
    const unavailable = await start({
      rows: [await rowFor(owner, 2), await rowFor(sibling, 2)],
    });
    expect(await runCli(["pull"], unavailable.env.layer)).toBe(0);
    expect(unavailable.posted).toEqual([]);
    expect(unavailable.env.errors.join("\n")).toContain(
      `your device ${sibling.fingerprintHex} has no keys for epoch 1 of environment ${ENV_ID}, and this device has none for them either, so it cannot fill them. A registered device of yours whose cap covers environment ${ENV_ID} and that holds its keys fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );

    const failing = await start({
      rows: [await rowFor(owner, 1), await rowFor(owner, 2), await rowFor(sibling, 2)],
      registerStatus: 500,
    });
    expect(await runCli(["pull"], failing.env.layer)).toBe(0);
    expect(failing.env.errors.join("\n")).toContain(
      `your device ${sibling.fingerprintHex} has no keys for epoch 1 of environment ${ENV_ID} (its backfill did not complete), and filling them from this device failed (`,
    );
    expect(failing.env.errors.join("\n")).toContain(
      `once the cause is fixed, the next \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\` tries again`,
    );

    // With a partially fillable gap (this device holds only epoch 2, the
    // sibling lacks both) when registration fails: the failure message
    // names only the epoch it tried to wrap (2), and the epoch this device
    // doesn't hold either (1) is also mentioned
    const partial = await start({
      rows: [await rowFor(owner, 2)],
      registerStatus: 500,
    });
    expect(await runCli(["pull"], partial.env.layer)).toBe(0);
    const partialErrors = partial.env.errors.join("\n");
    expect(partialErrors).toContain(
      `your device ${sibling.fingerprintHex} has no keys for epoch 2 of environment ${ENV_ID} (its backfill did not complete), and filling them from this device failed (`,
    );
    expect(partialErrors).toContain(
      `your device ${sibling.fingerprintHex} has no keys for epoch 1 of environment ${ENV_ID}, and this device has none for them either`,
    );
  });
});
