// Integration tests for the reserve-key handoff (CRYPTO_SPEC §8.4 /
// AUTH_SPEC §13-7 — KL3, 2026-09-19 DK K4): `maruhi key recover --handoff`
// (the requester) and `maruhi guardian approve <code>` (the approver).
// Ephemeral keys and share sealing/decryption are real crypto; the server is
// a wire-level mock.
//
// Properties pinned down:
//  1. The requester prints the code (the encoding of E.pub = public
//     information) to stderr; once enough guardian approvals arrive, it
//     decrypts reserve key B from the ledger's group wrap and — **without
//     storing it** — issues a fresh device key for this device (the
//     recovery tail — key-recover.ts). E.pub itself is never sent to the
//     server (only request_id). The old-device approval path (device
//     migration) was removed in K4
//  2. The approver (guardian) opens the share row sealed to their own
//     device key (`deviceShares`) and re-seals it to E.pub. Only the
//     ephemeral key's secret key can open it. An approval carries no blob
//     column
//  3. Anything but yes sends nothing. You cannot approve your own request.
//     Agent environments and non-terminals refuse both requesting and
//     approving

import {
  computeHandoffRequestId,
  decodeHandoffCode,
  decodeHex,
  encodeHandoffCode,
  encodeHex,
  type EncryptionKeyPair,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  generateMasterWrapKek,
  importEncryptionPublicKey,
  openHandoffValue,
  sealGuardianShare,
  sealHandoffValue,
  wrapMasterBlob,
} from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  masterKeyEntryName,
  parseStoredMasterKey,
  serializeStoredMasterKey,
  type StoredMasterKey,
  tokenEntryName,
} from "../src/keychain.ts";
import { appendableProjectHandlers, projectListHandlerOf } from "./support/chain-handler.ts";
import {
  addOwnerDeviceOp,
  buildChain,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let ward: TestUser;
/** ward's reserve key (the B the ledger seals — a different key from the device key). */
let reserve: TestUser;
let alice: TestUser;

const servers: MockServer[] = [];
const GROUP_ID = "01J9Z8Y7X6W5V4T3S2R1Q0P9N8";
const FAR_FUTURE_MS = Date.now() + 10 * 60 * 1000;

beforeAll(async () => {
  ward = await makeTestUser("user-ward-0001");
  reserve = await makeTestUser("user-ward-0001");
  alice = await makeTestUser("user-alice-0002");
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

const hex = (value: string): Uint8Array => {
  const bytes = decodeHex(value);
  if (bytes === null) throw new Error("hex");
  return bytes;
};

/** The key record the ledger holds (same shape as seedSession). */
function recordOf(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
    // The test's `reserve` is a CLI-generated reserve key (marked — DK K16).
    // Everything else is a device key
    ...(user === reserve ? { kind: "reserve" as const } : {}),
  };
}

interface Started {
  readonly env: TestEnv;
  readonly server: MockServer;
}

async function start(handlers: readonly MockHandler[]): Promise<Started> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  await seedConfig(env, { server: server.origin });
  return { env, server };
}

/** A new device with no key (token only). */
function seedTokenOnly(env: TestEnv, origin: string, user: TestUser): void {
  env.keychain.set(
    tokenEntryName(origin),
    JSON.stringify({ token: "maruhi_pat_stored", userId: user.userId, tokenId: "tok_1" }),
  );
}

/** The handoff code the requester printed to stderr (4 chars × 15 groups = 58 symbols + separators). */
function displayedCode(env: TestEnv): string {
  const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{2,4}){14}$/.test(entry));
  if (line === undefined) {
    throw new Error("handoff code line not found in stderr output");
  }
  return line.trim();
}

/** Recovers E.pub and request_id from the code (the same derivation as the approver side). */
async function decodeDisplayed(env: TestEnv): Promise<{
  readonly publicKey: Uint8Array;
  readonly requestId: string;
}> {
  const decoded = await decodeHandoffCode(displayedCode(env));
  if (!decoded.ok) throw new Error("code did not decode");
  const requestId = await computeHandoffRequestId(decoded.value);
  if (!requestId.ok) throw new Error("request id");
  return { publicKey: decoded.value, requestId: requestId.value };
}

/** The approval's distribution form (HandoffApprovalResult — no blob column). */
interface ApprovalWire {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverUserId: string;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly createdAtMs: number;
}

/** The ledger's group wrap (ward's reserve key B wrapped under the KEK — any: the KEK is the only share). */
async function wrappedReserve(kek: Uint8Array): Promise<{
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}> {
  const wrapped = await wrapMasterBlob({
    kek,
    masterSecretBlob: new TextEncoder().encode(serializeStoredMasterKey(recordOf(reserve))),
    context: { userId: ward.userId, kind: "guardian", wrapRef: GROUP_ID, mode: "any" },
  });
  if (!wrapped.ok) throw new Error("wrap");
  return {
    nonceHex: encodeHex(wrapped.value.nonce),
    ciphertextHex: encodeHex(wrapped.value.ciphertext),
  };
}

/**
 * Builds guardian `approver`'s approval server-side: re-seals the share
 * (= the KEK) to the E.pub read from the requester's display (E.pub is
 * carried by the human). `sealedAs` is the approver of the sealing context
 * (defaults to `approver` itself — a different person produces a
 * context-mismatched approval).
 */
async function guardianApprovalFor(
  env: TestEnv,
  approver: TestUser,
  kek: Uint8Array,
  sealedAs: TestUser = approver,
): Promise<ApprovalWire> {
  const { publicKey, requestId } = await decodeDisplayed(env);
  const ephemeral = await importEncryptionPublicKey(publicKey);
  if (!ephemeral.ok) throw new Error("ephemeral");
  const sealed = await sealHandoffValue({
    ephemeralPublicKey: ephemeral.value,
    value: kek,
    context: {
      userId: ward.userId,
      requestId,
      source: GROUP_ID,
      shareIndex: 1,
      approverUserId: sealedAs.userId,
    },
  });
  if (!sealed.ok) throw new Error("seal");
  return {
    source: GROUP_ID,
    shareIndex: 1,
    approverUserId: approver.userId,
    approverKeyFingerprintHex: approver.fingerprintHex,
    encHex: encodeHex(sealed.value.enc),
    ciphertextHex: encodeHex(sealed.value.ciphertext),
    createdAtMs: Date.now(),
  };
}

function statusHandler(groups: readonly unknown[]): MockHandler {
  return onRequest("GET", "/auth/key-wraps", () => ({
    status: 200,
    json: {
      recoveryCode: { registered: false, updatedAtMs: null },
      passkeys: [],
      guardianGroups: groups,
    },
  }));
}

/** An `any` group of alice alone (ledger state — share rows are per device). */
function aliceAnyGroup(): unknown {
  return {
    groupId: GROUP_ID,
    mode: "any",
    createdAtMs: 1754006400000,
    guardians: [
      {
        shareIndex: 1,
        guardianUserId: alice.userId,
        guardianKeyFingerprintHex: alice.fingerprintHex,
      },
    ],
  };
}

/** `POST /auth/handoff` — receives only request_id (E.pub never rides along). */
function createHandler(record: (body: { requestId: string }) => void): MockHandler {
  return onRequest("POST", "/auth/handoff", (request) => {
    record(request.body as { requestId: string });
    return { status: 200, json: { expiresAtMs: FAR_FUTURE_MS } };
  });
}

/** `GET /auth/handoff/:id/approvals` — returns the built approvals regardless of the path's request_id. */
function approvalsHandler(build: () => Promise<readonly ApprovalWire[]>): MockHandler {
  return (request) =>
    request.method === "GET" && /^\/auth\/handoff\/[0-9a-f]{64}\/approvals$/.test(request.path)
      ? build().then((approvals) => ({ status: 200, json: { approvals } }))
      : null;
}

/** `GET /auth/key-wraps/guardians/:groupId` — the ledger's group wrap (carries no shares). */
function groupHandler(wrap: {
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}): MockHandler {
  return onRequest("GET", `/auth/key-wraps/guardians/${GROUP_ID}`, () => ({
    status: 200,
    json: {
      groupId: GROUP_ID,
      mode: "any",
      wrap: { suite: "maruhi/v1", ...wrap },
      createdAtMs: 1754006400000,
    },
  }));
}

/** `GET /projects` — the project list the recovery tail scans (empty = nowhere to register). */
const noProjectsHandler: MockHandler = onRequest("GET", "/projects", () => ({
  status: 200,
  json: { projects: [] },
}));

const cancelHandler: MockHandler = (request) =>
  request.method === "DELETE" && /^\/auth\/handoff\/[0-9a-f]{64}$/.test(request.path)
    ? { status: 204 }
    : null;

describe("maruhi key recover --handoff (the requester)", () => {
  it("guardian (any): opens the ledger wrap with the share, never stores the reserve key, and issues a fresh device key", async () => {
    // Ledger: ward's reserve key B wrapped under the KEK, and the KEK (= the
    // `any` share) already sealed to alice
    const kek = generateMasterWrapKek();
    const chain = await buildChain([
      { actor: ward, operation: genesisOp(ward) },
      { actor: ward, operation: addOwnerDeviceOp(reserve) },
    ]);
    let createBody: { requestId: string } | null = null;
    const { env, server } = await start([
      createHandler((body) => {
        createBody = body;
      }),
      statusHandler([aliceAnyGroup()]),
      approvalsHandler(async () => [await guardianApprovalFor(env, alice, kek)]),
      groupHandler(await wrappedReserve(kek)),
      projectListHandlerOf([chain]),
      ...appendableProjectHandlers(chain),
      cancelHandler,
    ]);
    seedTokenOnly(env, server.origin, ward);
    // The recovery tail's single confirmation question (the reserve key is
    // a key ward's device added via add_device — DK K14)
    env.setPromptResponses(["yes"]);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(0);
    // request_id matches the code's derivation, and E.pub itself was never
    // sent
    const { publicKey, requestId } = await decodeDisplayed(env);
    expect((createBody as { requestId: string } | null)?.requestId).toBe(requestId);
    expect(JSON.stringify(server.requests.map((r) => r.body))).not.toContain(encodeHex(publicKey));
    // The keychain gets the **new device key**. The ledger's reserve key
    // (B) is not stored
    const stored = env.keychain.get(masterKeyEntryName(server.origin, ward.userId));
    expect(stored).toBeDefined();
    expect(stored).not.toContain(reserve.encSkHex);
    expect(stored).not.toContain(reserve.encPubHex);
    expect(stored).not.toContain(ward.encSkHex);
    const restored = parseStoredMasterKey(stored ?? "");
    if (restored === null) throw new Error("expected a device-key record in the keychain");
    expect(restored.encPubHex).not.toBe(reserve.encPubHex);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Handoff code (this is a public key, not a secret)");
    expect(errors).toContain(`Registered guardian groups: ${GROUP_ID} (any, 1 guardians)`);
    expect(errors).toContain(
      "the reserve key was discarded from memory; it stays sealed in the recovery ledger only. This device now signs with its own key",
    );
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `approved by ${alice.userId} (guardian, group ${GROUP_ID}; device key fingerprint ${alice.fingerprintHex})`,
    );
    expect(logs).toContain(
      `Opened key ${reserve.fingerprintHex} from the recovery ledger. It is used only to register this machine's new device key, then discarded`,
    );
    expect(logs).toContain("Generated this device's key");
    expect(logs).toMatch(/key fingerprint: [0-9a-f]{32}/);
    expect(logs).not.toContain(`key fingerprint: ${reserve.fingerprintHex}`);
    // A key marked as a reserve key is recorded without asking (DK K16-3 /
    // K16-6)
    expect(env.prompts).toEqual([]);
    expect(errors).toContain(
      `Note: recorded ${reserve.fingerprintHex} on this machine as your reserve key (its ledger record carries the mark maruhi writes when it creates a reserve key)`,
    );
    // No key material appears in the output
    expect(logs).not.toContain(reserve.encSkHex);
    expect(errors).not.toContain(reserve.encSkHex);
    // It fetches the ledger wrap and deletes the request that served its
    // purpose
    expect(
      server.requests.some(
        (r) => r.method === "GET" && r.path === `/auth/key-wraps/guardians/${GROUP_ID}`,
      ),
    ).toBe(true);
    expect(server.requests.some((r) => r.method === "DELETE")).toBe(true);
  });

  it("an approval mismatched to the request's context fails to decrypt and stores no key", async () => {
    const kek = generateMasterWrapKek();
    const { env, server } = await start([
      createHandler(() => {}),
      statusHandler([aliceAnyGroup()]),
      // The sealing context's approver (ward) differs from the attested
      // approver (alice) → cannot be opened
      approvalsHandler(async () => [await guardianApprovalFor(env, alice, kek, ward)]),
      groupHandler(await wrappedReserve(kek)),
      noProjectsHandler,
      cancelHandler,
    ]);
    seedTokenOnly(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Cannot open the approval from ${alice.userId}: it was not sealed to this request's key, or its context was altered in transit. The handoff was aborted — re-run and hand the new code to the guardians again`,
    );
    expect(env.keychain.get(masterKeyEntryName(server.origin, ward.userId))).toBeUndefined();
    // Never reaches the ledger wrap
    expect(server.requests.some((r) => r.path === `/auth/key-wraps/guardians/${GROUP_ID}`)).toBe(
      false,
    );
  });

  it("creates no request and suggests another unsealing means when there is no guardian", async () => {
    const { env, server } = await start([createHandler(() => {}), statusHandler([])]);
    seedTokenOnly(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "You have no guardians registered, so nobody can approve a handoff. Open the reserve key with your recovery code (`maruhi key recover`) or a passkey (`--passkey`) instead",
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("refuses the request on a device that already has a key", async () => {
    const { env, server } = await start([createHandler(() => {})]);
    seedSession(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "A device key already exists on this machine, so there is nothing to recover here. To add this machine as another device of yours, run `maruhi device add` and approve it from a registered device; if an earlier `maruhi key recover` was interrupted before every project registered this device, re-run with --resume",
    );
    expect(server.requests).toHaveLength(0);
  });

  it("refuses the request in agent environments and non-terminals", async () => {
    const { env, server } = await start([createHandler(() => {})]);
    seedTokenOnly(env, server.origin, ward);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to request a key handoff because an AI agent environment was detected (the restored reserve key would land in the agent's session; run this yourself on a human interactive terminal)",
    );
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdout: false });
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Key handoff requests are only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
    );
    expect(server.requests).toHaveLength(0);
  });
});

/** The requester's ephemeral key and code (the test plays the requester). */
async function makeRequester(): Promise<{
  readonly keyPair: EncryptionKeyPair;
  readonly code: string;
  readonly requestId: string;
}> {
  const keyPair = await generateEncryptionKeyPair();
  const publicKey = await exportEncryptionPublicKey(keyPair.publicKey);
  const code = await encodeHandoffCode(publicKey);
  const requestId = await computeHandoffRequestId(publicKey);
  if (!code.ok || !requestId.ok) throw new Error("code");
  return { keyPair, code: code.value, requestId: requestId.value };
}

/** The approval's payload (HandoffApproval — no blob column). */
interface ApproveBody {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** The lookup response (`roles` is only the guardian-share shape — the legacy "device" is gone). */
function lookupOf(wardUser: TestUser, wardLogin: string | null): unknown {
  return {
    wardUserId: wardUser.userId,
    wardLogin,
    expiresAtMs: FAR_FUTURE_MS,
    roles: [{ groupId: GROUP_ID, mode: "any", shareIndex: 1 }],
  };
}

function lookupHandler(requestId: string, json: unknown): MockHandler {
  return onRequest("GET", `/auth/handoff/${requestId}`, () => ({ status: 200, json }));
}

function approveHandler(requestId: string, record: (body: ApproveBody) => void): MockHandler {
  return onRequest("POST", `/auth/handoff/${requestId}/approvals`, (request) => {
    record(request.body as ApproveBody);
    return { status: 204 };
  });
}

/** The ledger's share (the KEK sealed to guardian `guardian`'s device key). */
async function sealedShareFor(
  guardian: TestUser,
  kek: Uint8Array,
): Promise<{ readonly encHex: string; readonly ciphertextHex: string }> {
  const publicKey = await importEncryptionPublicKey(hex(guardian.encPubHex));
  if (!publicKey.ok) throw new Error("guardian pub");
  const share = await sealGuardianShare({
    guardianPublicKey: publicKey.value,
    share: kek,
    context: {
      userId: ward.userId,
      groupId: GROUP_ID,
      mode: "any",
      shareIndex: 1,
      guardianUserId: guardian.userId,
    },
  });
  if (!share.ok) throw new Error("share");
  return { encHex: encodeHex(share.value.enc), ciphertextHex: encodeHex(share.value.ciphertext) };
}

/**
 * `GET /auth/guardian/shares/:groupId` (GuardianShareResult): the leading
 * row's fields plus `deviceShares` (all of your device rows — K3-10).
 * Omitting `deviceShares` yields the legacy-server shape.
 */
function myShareHandler(
  rows: readonly {
    readonly guardianKeyFingerprintHex: string;
    readonly guardianEncPubHex: string;
    readonly encHex: string;
    readonly ciphertextHex: string;
  }[],
  options: { readonly legacy?: boolean } = {},
): MockHandler {
  const head = rows[0];
  if (head === undefined) throw new Error("at least one row");
  return onRequest("GET", `/auth/guardian/shares/${GROUP_ID}`, () => ({
    status: 200,
    json: {
      groupId: GROUP_ID,
      wardUserId: ward.userId,
      mode: "any",
      shareIndex: 1,
      encHex: head.encHex,
      ciphertextHex: head.ciphertextHex,
      ...(options.legacy === true ? {} : { deviceShares: rows }),
    },
  }));
}

describe("maruhi guardian approve <code> (the approver)", () => {
  it("guardian: opens the share row addressed to their device and re-seals to E.pub (any)", async () => {
    const requester = await makeRequester();
    const kek = generateMasterWrapKek();
    // The ledger's share rows: a row for alice's device key and a dummy
    // row for another (e.g. revoked) device
    const mine = await sealedShareFor(alice, kek);
    const other = await sealedShareFor(ward, kek);
    let approved: ApproveBody | null = null;
    const { env, server } = await start([
      lookupHandler(requester.requestId, lookupOf(ward, null)),
      myShareHandler([
        {
          guardianKeyFingerprintHex: "00".repeat(16),
          guardianEncPubHex: ward.encPubHex,
          ...other,
        },
        {
          guardianKeyFingerprintHex: alice.fingerprintHex,
          guardianEncPubHex: alice.encPubHex,
          ...mine,
        },
      ]),
      approveHandler(requester.requestId, (body) => {
        approved = body;
      }),
    ]);
    seedSession(env, server.origin, alice);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(0);
    const body = approved as ApproveBody | null;
    if (body === null) throw new Error("no approval");
    expect(body.source).toBe(GROUP_ID);
    expect(body.shareIndex).toBe(1);
    expect(body.approverKeyFingerprintHex).toBe(alice.fingerprintHex);
    expect(body).not.toHaveProperty("blob");
    const opened = await openHandoffValue({
      ephemeralKeyPair: requester.keyPair,
      wrapped: { enc: hex(body.encHex), ciphertext: hex(body.ciphertextHex) },
      context: {
        userId: ward.userId,
        requestId: requester.requestId,
        source: GROUP_ID,
        shareIndex: 1,
        approverUserId: alice.userId,
      },
    });
    if (!opened.ok) throw new Error("open");
    expect(opened.value).toEqual(kek);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`Handoff request from ${ward.userId} — you are their guardian`);
    expect(logs).toContain(`  groups: ${GROUP_ID} (any, share 1)`);
    expect(logs).toContain(`Approved share 1 of group ${GROUP_ID}`);
    expect(env.prompts).toContain(`Type yes to approve the handoff for ${ward.userId}: `);
    expect(env.errors.join("\n")).toContain(
      "the approval was sealed to the requester's one-time key and nothing was stored on this device",
    );
    // The share, KEK, and secret key never appear in the output
    expect(logs).not.toContain(encodeHex(kek));
    expect(logs).not.toContain(alice.encSkHex);
    expect(env.errors.join("\n")).not.toContain(alice.encSkHex);
  });

  it("guardian: a legacy server (no deviceShares) opens the leading row as this device's share", async () => {
    const requester = await makeRequester();
    const kek = generateMasterWrapKek();
    let approved: ApproveBody | null = null;
    const { env, server } = await start([
      lookupHandler(requester.requestId, lookupOf(ward, "ward-login")),
      myShareHandler(
        [
          {
            guardianKeyFingerprintHex: alice.fingerprintHex,
            guardianEncPubHex: alice.encPubHex,
            ...(await sealedShareFor(alice, kek)),
          },
        ],
        { legacy: true },
      ),
      approveHandler(requester.requestId, (body) => {
        approved = body;
      }),
    ]);
    seedSession(env, server.origin, alice);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(0);
    const body = approved as ApproveBody | null;
    if (body === null) throw new Error("no approval");
    const opened = await openHandoffValue({
      ephemeralKeyPair: requester.keyPair,
      wrapped: { enc: hex(body.encHex), ciphertext: hex(body.ciphertextHex) },
      context: {
        userId: ward.userId,
        requestId: requester.requestId,
        source: GROUP_ID,
        shareIndex: 1,
        approverUserId: alice.userId,
      },
    });
    if (!opened.ok) throw new Error("open");
    expect(opened.value).toEqual(kek);
    expect(env.logs.join("\n")).toContain(
      `Handoff request from ward-login (${ward.userId}) — you are their guardian`,
    );
  });

  it("guardian: sends nothing when no share row is addressed to this device", async () => {
    const requester = await makeRequester();
    const kek = generateMasterWrapKek();
    const { env, server } = await start([
      lookupHandler(requester.requestId, lookupOf(ward, null)),
      // Only a row addressed to alice's other device (no row with this
      // device's FP)
      myShareHandler([
        {
          guardianKeyFingerprintHex: "00".repeat(16),
          guardianEncPubHex: alice.encPubHex,
          ...(await sealedShareFor(alice, kek)),
        },
      ]),
      approveHandler(requester.requestId, () => {}),
    ]);
    seedSession(env, server.origin, alice);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Your share of group ${GROUP_ID} is not sealed to this device (fingerprint ${alice.fingerprintHex}). Approve from one of your devices it was sealed to, or ask ${ward.userId} to re-add the group after this device was registered`,
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("you cannot approve your own request (device migration does not go through the handoff)", async () => {
    const requester = await makeRequester();
    const { env, server } = await start([
      // Even if the server wrongly shows the request to ward themself,
      // refuse locally
      lookupHandler(requester.requestId, lookupOf(ward, null)),
      approveHandler(requester.requestId, () => {}),
    ]);
    seedSession(env, server.origin, ward);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "This handoff request is your own. Only your guardians can approve it (device migration no longer goes through a handoff — register a new device with `maruhi device add` / `maruhi device approve`)",
    );
    expect(env.prompts).toHaveLength(0);
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("anything but yes sends nothing / an unknown request is guided / a malformed code is refused", async () => {
    const requester = await makeRequester();
    const { env, server } = await start([
      lookupHandler(requester.requestId, lookupOf(ward, null)),
      approveHandler(requester.requestId, () => {}),
      (request) =>
        request.method === "GET" && /^\/auth\/handoff\/[0-9a-f]{64}$/.test(request.path)
          ? { status: 404, json: { _tag: "HandoffNotFound" } }
          : null,
    ]);
    seedSession(env, server.origin, alice);
    env.setPromptResponses(["no"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The handoff approval was cancelled (nothing was sent)",
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);

    const other = await makeRequester();
    expect(await runCli(["guardian", "approve", other.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "No pending handoff request matches this code (it is unknown, expired, or you are not one of the requester's guardians)",
    );

    expect(await runCli(["guardian", "approve", requester.code.slice(0, -1)], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The handoff code is malformed (58 characters in groups of 4; hyphens, spaces, and letter case are ignored). Copy it again from the requesting device",
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("refuses to approve in agent environments and non-terminals", async () => {
    const requester = await makeRequester();
    const { env, server } = await start([approveHandler(requester.requestId, () => {})]);
    seedSession(env, server.origin, alice);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to approve a key handoff because an AI agent environment was detected (approving hands out key material; run this yourself on a human interactive terminal)",
    );
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Key handoff approvals are only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
    );
    expect(server.requests).toHaveLength(0);
  });
});
