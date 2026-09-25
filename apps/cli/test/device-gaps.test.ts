// 同じ人の他の端末の欠けたエポックの補完(DK K11 — 設計録 dk-design.md §16)の統合テスト。
// 端末 op・ラップ・登録署名は実 crypto、サーバーはワイヤレベルモック。
//
// 固定する性質(K11-6):
//  1. `maruhi pull` は同梱のラップの行から、同じ人の他の有効な端末のうちその環境の受信者で
//     あるものの欠けたエポックを導き、**そのエポックだけ**を兄弟の鍵宛に包み、この端末の
//     登録署名で登録する(登録された行は兄弟の鍵で開け、§5.1 の署名が通る)
//  2. 欠けが無い・旧サーバーの行(`recipientEncPubHex` 無し)・受信者でない端末(実効 scope の
//     外)では登録しない
//  3. この端末も開けないエポックは包まず報告する。登録の失敗は Note で、pull は 0 のまま

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
/** owner の 2 台目(欠けたエポックを持つ兄弟端末)。 */
let sibling: TestUser;
/** owner の 3 台目(cap の scope が OTHER_ENV_ID だけ — ENV_ID の受信者ではない)。 */
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

/** 端末鍵宛の配布行(新サーバーの形 — `recipientEncPubHex` つき)。 */
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

/** チェーン + 変数 0 の環境の値付き pull(同梱の行を差し替える)+ ラップ登録。 */
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

describe("maruhi pull が同じ人の他の端末の欠けたエポックを補う(DK K11)", () => {
  it("兄弟の欠けたエポックだけを、兄弟の鍵宛にこの端末の登録署名で登録する", async () => {
    // owner は 1・2 を持ち、sibling は 2 だけ(1 が欠け)。narrow は ENV_ID の受信者でない
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
    // 宛先の取り違えを落とす: 兄弟の鍵で開けて epoch 1 の DEK になり、登録署名が通る
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

  it("欠けが無い・旧サーバーの行・受信者でない端末の欠けでは登録しない", async () => {
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

    // 旧サーバー(行に `recipientEncPubHex` が無い = 帰属が分からない)は導かない
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

  it("この端末も開けないエポックは包まず報告し、登録の失敗は Note に留めて pull は 0", async () => {
    // owner も epoch 1 を持たない → sibling の epoch 1 は補えない(包まない)
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

    // 一部だけ補える欠け(この端末は epoch 2 だけ、兄弟は両方欠け)で登録が失敗したとき:
    // 失敗の文は包もうとしたエポック(2)だけを言い、この端末も持たないエポック(1)の文も出す
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
