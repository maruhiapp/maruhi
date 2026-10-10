// Tests for `maruhi ci rotate` (CRYPTO_SPEC §5.3 / AUTH_SPEC §14-5 — PF7b).
//
// The lease endpoint and the proposal mint are impersonated by MockServer
// (the lease wraps are built with real crypto to the request's ephemeral
// key; the mint records the body). OIDC issuance is a MockServer path
// (dummy signature). The connector is the `exec` connector with a faked
// script (setCaptureHandler). Server-side decisions are pinned by
// apps/server/test/rotation-proposals.test.ts; this file pins the client:
//  1. the proposal is sealed to exactly W(E) — member-or-above devices in
//     scope (the reader is not a recipient) — and each wrap opens with
//     that device's key to the new value, under the lease's token and key
//  2. the current credential and the admin input reach the script from
//     the lease, in memory; no value is printed or sent in the clear
//  3. a rule without a grace period is refused before the issuer is touched
//  4. a server refusal after the issuer accepted names the recovery step
//  5. the required flags are usage errors (2) before any network

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ChainOperation, EncryptionKeyPair } from "@maruhi/crypto";
import {
  computeLeaseClaimsDigest,
  encodeHex,
  importEncryptionPublicKey,
  openProposedValue,
  wrapLeaseDek,
} from "@maruhi/crypto";
import { Clock, Duration, Effect, Layer, Redacted } from "effect";
import { TestClock } from "effect/testing";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  issuanceBoundFor,
  OIDC_REQUEST_TOKEN_ENV,
  OIDC_REQUEST_URL_ENV,
} from "../src/oidc-github.ts";
import {
  addMemberOp,
  buildChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes as toBytes,
  makeTestUser,
  manifestFor,
  statementFor,
  testEnvironmentId,
  testProjectId,
  testUserId,
  testVariableId,
  type BuiltChain,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, type TestEnv } from "./support/env.ts";
import {
  type MockHandler,
  type MockRequest,
  type MockResponse,
  MockServer,
} from "./support/server.ts";

const ENV_ID = "prod";
const ISSUER = "https://token.actions.githubusercontent.com";
const RUNNER_TOKEN = "runner-request-token-value";
const OLD_KEY = "sk_live_old_dummy";
const NEW_KEY = "sk_live_new_dummy";
const ADMIN_KEY = "rk_admin_dummy";
const OLD_ID = "rk_id_old_dummy";
const NEW_ID = "rk_id_new_dummy";

interface PullEntry {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

let owner: TestUser;
/** The owner's second device (cap owner — a recipient) and a reader-capped device (never a recipient). */
let ownerPhone: TestUser;
let ownerReaderCap: TestUser;
let member: TestUser;
let reader: TestUser;
let built: BuiltChain;
let dek: Uint8Array;
let envStatement: WireDistributedEnvironmentStatement;
let entries: PullEntry[];
let servers: MockServer[] = [];

/** `add_device` with a role cap (CRYPTO_SPEC §6.2 — the actor is a valid device of the same person). */
function addDeviceOp(
  device: TestUser,
  roleCap: "owner" | "admin" | "member" | "reader",
): ChainOperation {
  return {
    op: "add_device",
    payload: {
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap,
      scopeKind: "all",
      scopeEnvironmentIds: [],
    },
  };
}

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  ownerPhone = await makeTestUser("user-owner-1111");
  ownerReaderCap = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  reader = await makeTestUser("user-reader-3333");
  dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
    { actor: owner, operation: addMemberOp(member, "member") },
    { actor: owner, operation: addMemberOp(reader, "reader") },
    { actor: owner, operation: addDeviceOp(ownerPhone, "owner") },
    { actor: owner, operation: addDeviceOp(ownerReaderCap, "reader") },
    {
      actor: owner,
      operation: await grantServerOp(
        [ENV_ID],
        [{ issuerUrl: ISSUER, audience: "https://maruhi.example", claimConstraints: [] }],
      ),
    },
  ]);
  const genesisHead = { seq: 1, hashHex: built.projectId };
  const head = headOf(built, built.entries.length);
  envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: genesisHead,
  });
  const entry = async (variableId: string, name: string, plaintext: string, version: number) => ({
    variableId,
    statement: await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId,
      name,
      author: owner,
      head: genesisHead,
    }),
    value: await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId,
      version,
      plaintext,
      writer: owner,
      head,
    }),
  });
  entries = [
    await entry("vs", "STRIPE_SECRET_KEY", OLD_KEY, 3),
    await entry("va", "STRIPE_ADMIN_KEY", ADMIN_KEY, 1),
    await entry("vk", "STRIPE_KEY_ID", OLD_ID, 1),
  ];
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function fakeJwt(payload: Record<string, unknown>): string {
  return `${base64UrlJson({ alg: "RS256", kid: "k1" })}.${base64UrlJson(payload)}.c2lnbmF0dXJl`;
}

function jwtPayload(token: string): Record<string, unknown> {
  const segment = token.split(".")[1] ?? "";
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;
}

interface OidcOptions {
  /** The `exp` (seconds) of every token issued (default: none). */
  readonly expSeconds?: number;
  /** After this many tokens the endpoint answers 500 (default: never). */
  readonly failAfter?: number;
  /** After this many tokens the endpoint hangs (answers only after a minute — the fetch's bound ends the wait). */
  readonly hangAfter?: number;
  /** After this many tokens the endpoint answers late, after `delayMs` (a slow runner endpoint; default 3 s). */
  readonly delayAfter?: number;
  readonly delayMs?: number;
}

/** The endpoint's injected outage after `issued` tokens: a 500, or an answer only after a minute (the fetch's bound ends the wait). */
function issuanceOutage(
  issued: number,
  options: OidcOptions,
): MockResponse | Promise<MockResponse> | null {
  if (options.failAfter !== undefined && issued >= options.failAfter) {
    return { status: 500, json: { message: "issuance unavailable" } };
  }
  if (options.hangAfter !== undefined && issued >= options.hangAfter) {
    return new Promise((resolve) => {
      setTimeout(() => resolve({ status: 500, json: { message: "late" } }), 60_000).unref();
    });
  }
  return null;
}

/** A delayed `null` (the token is issued, late) after `delayAfter` tokens. */
function issuanceDelay(issued: number, options: OidcOptions): Promise<null> | null {
  if (options.delayAfter === undefined || issued < options.delayAfter) {
    return null;
  }
  return new Promise((resolve) => {
    setTimeout(() => resolve(null), options.delayMs ?? 3000).unref();
  });
}

function oidcHandler(
  state: { issued: number; fetches: number },
  options: OidcOptions = {},
): MockHandler {
  return (request) => {
    if (request.method !== "GET" || request.path !== "/oidc/token") {
      return null;
    }
    if (request.headers["authorization"] !== `Bearer ${RUNNER_TOKEN}`) {
      return { status: 401, json: { message: "bad runner token" } };
    }
    state.fetches += 1;
    const outage = issuanceOutage(state.issued, options);
    if (outage !== null) {
      return outage;
    }
    const issue = (): MockResponse => {
      state.issued += 1;
      return {
        status: 200,
        json: {
          value: fakeJwt({
            iss: ISSUER,
            sub: `repo:acme/app:ref:refs/heads/main/run/${state.issued}`,
            aud: request.query["audience"] ?? "",
            jti: state.issued,
            ...(options.expSeconds === undefined ? {} : { exp: options.expSeconds }),
          }),
        },
      };
    };
    const delay = issuanceDelay(state.issued, options);
    return delay === null ? issue() : delay.then(issue);
  };
}

async function leaseWrapFor(body: { oidcToken: string; ephemeralPubHex: string }) {
  const payload = jwtPayload(body.oidcToken);
  const digest = await computeLeaseClaimsDigest({
    issuerUrl: String(payload["iss"]),
    subject: String(payload["sub"]),
    audience: String(payload["aud"]),
  });
  const publicKey = await importEncryptionPublicKey(toBytes(body.ephemeralPubHex));
  if (!digest.ok || !publicKey.ok) {
    throw new Error("lease fixture failed");
  }
  const wrapped = await wrapLeaseDek({
    workloadPublicKey: publicKey.value,
    dek,
    context: {
      projectId: testProjectId(built.projectId),
      environmentId: testEnvironmentId(ENV_ID),
      epoch: 1,
      claimsDigestHex: digest.value,
    },
  });
  if (!wrapped.ok) {
    throw new Error("lease wrap failed");
  }
  return {
    suite: "maruhi/v1",
    epoch: 1,
    encHex: encodeHex(wrapped.value.enc),
    ciphertextHex: encodeHex(wrapped.value.ciphertext),
  };
}

interface Leased {
  readonly bodies: { oidcToken: string; ephemeralPubHex: string }[];
}

function leaseHandler(leased: Leased): MockHandler {
  return async (request) => {
    if (
      request.method !== "POST" ||
      request.path !== `/projects/${built.projectId}/environments/${ENV_ID}/lease`
    ) {
      return null;
    }
    const body = request.body as { oidcToken: string; ephemeralPubHex: string };
    leased.bodies.push(body);
    return {
      status: 200,
      json: {
        projectId: built.projectId,
        environmentId: ENV_ID,
        currentEpoch: 1,
        chain: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
        statement: envStatement,
        variables: entries,
        deletedVariables: [],
        manifest: await manifestFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          issuer: owner,
          head: headOf(built, built.entries.length),
          envStatement,
          statements: entries.map((entry) => entry.statement),
        }),
        leases: [await leaseWrapFor(body)],
        schemaPolicy: "enabled" as const,
      },
    };
  };
}

interface MintBody {
  readonly oidcToken: string;
  readonly ephemeralPubHex: string;
  readonly proposal: {
    readonly proposalId: string;
    readonly connector: string;
    readonly facts: readonly string[];
    readonly expiresInDays: number;
    readonly variables: readonly {
      readonly variableId: string;
      readonly baseVersion: number;
      readonly wraps: readonly {
        readonly recipientUserId: string;
        readonly recipientEncPubHex: string;
        readonly encHex: string;
        readonly ciphertextHex: string;
      }[];
    }[];
  };
}

interface Minted {
  readonly requests: MockRequest[];
  readonly bodies: MintBody[];
  /** An injected refusal (undefined = accept). */
  reject?: { status: number; json: unknown } | undefined;
  /** An injected refusal of the next mint only. */
  rejectOnce?: { status: number; json: unknown } | undefined;
}

function mintHandler(minted: Minted): MockHandler {
  return (request) => {
    if (
      request.method !== "POST" ||
      request.path !== `/projects/${built.projectId}/environments/${ENV_ID}/rotation-proposals`
    ) {
      return null;
    }
    minted.requests.push(request);
    const body = request.body as MintBody;
    minted.bodies.push(body);
    if (minted.reject !== undefined) {
      return minted.reject;
    }
    if (minted.rejectOnce !== undefined) {
      const once = minted.rejectOnce;
      minted.rejectOnce = undefined;
      return once;
    }
    // The server sets the instant from the days (the receipt)
    return {
      status: 200,
      json: {
        proposalId: body.proposal.proposalId,
        expiresAtMs: Date.now() + body.proposal.expiresInDays * 24 * 60 * 60 * 1000,
      },
    };
  };
}

const EXEC_RULE = {
  version: 1,
  variables: {
    STRIPE_SECRET_KEY: {
      connector: "exec",
      rotate: ["./rotate.sh"],
      finalize: ["./finalize.sh"],
      inputs: { STRIPE_ADMIN_KEY: "STRIPE_ADMIN_KEY" },
    },
  },
};

interface PreflightBody {
  readonly oidcToken: string;
  readonly ephemeralPubHex: string;
  readonly variables: readonly { variableId: string; baseVersion: number }[];
  readonly recipients: readonly { userId: string; encPubHex: string }[];
}

interface Preflighted {
  readonly bodies: PreflightBody[];
  /** An injected refusal (undefined = ok). */
  reject?: { status: number; json: unknown } | undefined;
}

function preflightHandler(preflighted: Preflighted): MockHandler {
  return (request) => {
    if (
      request.method !== "POST" ||
      request.path !==
        `/projects/${built.projectId}/environments/${ENV_ID}/rotation-proposals/preflight`
    ) {
      return null;
    }
    preflighted.bodies.push(request.body as PreflightBody);
    return preflighted.reject ?? { status: 200, json: { ok: true } };
  };
}

interface CiFixture {
  readonly env: TestEnv;
  readonly server: MockServer;
  readonly configPath: string;
  readonly leased: Leased;
  readonly preflighted: Preflighted;
  readonly minted: Minted;
  /** The issuance endpoint's counters (a fetch in flight already holds its bound). */
  readonly oidc: { issued: number; fetches: number };
}

/** CI environment: neither login nor config is seeded (CI mode's independence is pinned by this setup). */
async function startCi(config: unknown = EXEC_RULE, oidc: OidcOptions = {}): Promise<CiFixture> {
  const leased: Leased = { bodies: [] };
  const preflighted: Preflighted = { bodies: [] };
  const minted: Minted = { requests: [], bodies: [] };
  const oidcState = { issued: 0, fetches: 0 };
  const server = await MockServer.start([
    oidcHandler(oidcState, oidc),
    leaseHandler(leased),
    preflightHandler(preflighted),
    mintHandler(minted),
  ]);
  servers.push(server);
  const env = await makeTestEnv();
  env.setEnvVar(OIDC_REQUEST_URL_ENV, `${server.origin}/oidc/token`);
  env.setEnvVar(OIDC_REQUEST_TOKEN_ENV, RUNNER_TOKEN);
  env.setCaptureHandler((call) => ({
    exitCode: 0,
    stdout: new TextEncoder().encode(
      call.extraEnv["MH_ROTATE_PHASE"] === "rotate" ? `${NEW_KEY}\n` : "done\n",
    ),
    stderr: "",
  }));
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-ci-rotate-test-"));
  const configPath = join(configDir, "maruhi.rotate.json");
  await writeFile(configPath, JSON.stringify(config));
  return { env, server, configPath, leased, preflighted, minted, oidc: oidcState };
}

function ciRotateArgs(fixture: CiFixture, extra: readonly string[]): string[] {
  return [
    "ci",
    "rotate",
    "STRIPE_SECRET_KEY",
    "--server",
    fixture.server.origin,
    "--project",
    built.projectId,
    "--env",
    ENV_ID,
    "--rotate-config",
    fixture.configPath,
    ...extra,
  ];
}

function ciRotate(fixture: CiFixture, ...extra: string[]): Promise<number> {
  return runCli(ciRotateArgs(fixture, extra), fixture.env.layer);
}

/** The same rotation run against a TestClock (the job's clock reads come from it). */
function ciRotateOnClock(
  fixture: CiFixture,
  clock: Clock.Clock,
  ...extra: string[]
): Promise<number> {
  return runCli(
    ciRotateArgs(fixture, extra),
    Layer.mergeAll(fixture.env.layer, Layer.succeed(Clock.Clock, clock)),
  );
}

/**
 * A TestClock pinned at the real current instant: the job's clock reads are
 * controllable while the mock server and the code outside the Effect context
 * (which still read real time) stay consistent with it. Returns the instant
 * the clock was set to, for computing token expirations.
 */
async function realNowClock(): Promise<{ clock: Clock.Clock; nowMs: number }> {
  const clock = await Effect.runPromise(
    Effect.gen(function* () {
      return yield* Clock.Clock;
    }).pipe(Effect.provide(TestClock.layer())),
  );
  const nowMs = Date.now();
  await Effect.runPromise(TestClock.setTime(nowMs).pipe(Effect.provideService(Clock.Clock, clock)));
  return { clock, nowMs };
}

/** Advances the run's clock past any timeouts scheduled inside the interval. */
function clockAdjust(clock: Clock.Clock, millis: number): Promise<void> {
  return Effect.runPromise(
    TestClock.adjust(Duration.millis(millis)).pipe(Effect.provideService(Clock.Clock, clock)),
  );
}

/** Waits until the mock's issuance endpoint has been hit `count` times (the fetch then holds its bound). */
async function oidcFetches(fixture: CiFixture, count: number): Promise<void> {
  const deadline = Date.now() + 4_000;
  while (fixture.oidc.fetches < count) {
    if (Date.now() > deadline) {
      throw new Error(
        `the OIDC endpoint was hit ${fixture.oidc.fetches} times, expected at least ${count}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function expectNoSecretLeak(fixture: CiFixture): void {
  const shown = [
    ...fixture.env.logs,
    ...fixture.env.errors,
    ...fixture.minted.requests.map((request) => request.path),
    ...fixture.minted.bodies.map((body) => JSON.stringify(body.proposal)),
  ].join("\n");
  for (const secret of [OLD_KEY, NEW_KEY, ADMIN_KEY, RUNNER_TOKEN, OLD_ID, NEW_ID]) {
    expect(shown).not.toContain(secret);
  }
}

async function openWith(
  pair: EncryptionKeyPair,
  userId: string,
  body: MintBody,
  wrap: MintBody["proposal"]["variables"][number]["wraps"][number],
  target: { readonly variableId: string; readonly baseVersion: number } = {
    variableId: "vs",
    baseVersion: 3,
  },
): Promise<string | null> {
  const opened = await openProposedValue({
    recipientKeyPair: pair,
    sealed: { enc: toBytes(wrap.encHex), ciphertext: toBytes(wrap.ciphertextHex) },
    context: {
      projectId: testProjectId(built.projectId),
      environmentId: testEnvironmentId(ENV_ID),
      proposalId: body.proposal.proposalId,
      variableId: testVariableId(target.variableId),
      baseVersion: target.baseVersion,
      recipientUserId: testUserId(userId),
    },
  });
  return opened.ok ? new TextDecoder().decode(opened.value) : null;
}

/** The owner's devices in the order the client seals to them (fingerprint order — devicesOf). */
function ownerDevicesInOrder(): readonly TestUser[] {
  return [owner, ownerPhone].toSorted((a, b) =>
    a.fingerprintHex < b.fingerprintHex ? -1 : a.fingerprintHex > b.fingerprintHex ? 1 : 0,
  );
}

/** Opens the owner's wraps, each with the device the wrap is addressed to (same order as ownerDevicesInOrder). */
function openedByOwnerDevices(
  body: MintBody,
  wraps: readonly MintBody["proposal"]["variables"][number]["wraps"][number][],
): Promise<readonly (string | null)[]> {
  return Promise.all(
    ownerDevicesInOrder().map((device, index) => {
      const own = wraps[index];
      return own === undefined
        ? Promise.resolve(null)
        : openWith(device.encKeyPair, owner.userId, body, own);
    }),
  );
}

/** The one mint of a run (a missing or second mint fails the test). */
function onlyMint(fixture: CiFixture): MintBody {
  expect(fixture.minted.bodies).toHaveLength(1);
  return nth(fixture.minted.bodies, 0);
}

/** The `jti` of a body's token (the issuance order of the mock's tokens). */
function jtiOf(body: { readonly oidcToken: string }): unknown {
  return jwtPayload(body.oidcToken)["jti"];
}

function nth<T>(items: readonly T[], index: number): T {
  const item = items[index];
  if (item === undefined) {
    throw new Error(`no item at index ${index}`);
  }
  return item;
}

describe("maruhi ci rotate (sealed value proposals — PF7b)", () => {
  it("runs the connector from the lease and stores the new value sealed to every member device in scope, under the lease's key and a fresh token", async () => {
    const fixture = await startCi();
    expect(await ciRotate(fixture)).toBe(0);

    // The script saw the leased credential and admin input (memory only)
    expect(fixture.env.captureCalls).toHaveLength(1);
    const call = fixture.env.captureCalls[0];
    expect(call?.command).toEqual(["./rotate.sh"]);
    expect(call?.extraEnv["STRIPE_SECRET_KEY"]).toBe(OLD_KEY);
    expect(call?.extraEnv["STRIPE_ADMIN_KEY"]).toBe(ADMIN_KEY);
    expect(call?.extraEnv["MH_ROTATE_PHASE"]).toBe("rotate");

    // The pre-flight ran before the connector, under the lease's own
    // credential, naming the leased versions (O-4)
    expect(fixture.leased.bodies).toHaveLength(1);
    const lease = nth(fixture.leased.bodies, 0);
    expect(fixture.preflighted.bodies).toEqual([
      {
        oidcToken: lease.oidcToken,
        ephemeralPubHex: lease.ephemeralPubHex,
        variables: [{ variableId: "vs", baseVersion: 3 }],
        // The set the job seals to, named before the issuer is touched (O-11)
        recipients: onlyMint(fixture).proposal.variables[0]?.wraps.map((wrap) => ({
          userId: wrap.recipientUserId,
          encPubHex: wrap.recipientEncPubHex,
        })),
      },
    ]);
    // One mint, under the lease's ephemeral key and a token minted for it
    // after the connector (K-5 — the lease's token may have aged out)
    const body = onlyMint(fixture);
    expect(body.oidcToken).not.toBe(lease.oidcToken);
    expect(jwtPayload(body.oidcToken)["jti"]).toBe(2);
    expect(body.ephemeralPubHex).toBe(lease.ephemeralPubHex);
    expect(body.proposal.proposalId).toMatch(/^[0-9a-f]{32}$/);
    expect(body.proposal.connector).toBe("exec");
    // The value's shape is shown locally, never stored with the proposal (D-8)
    expect(body.proposal.facts).toEqual(["./rotate.sh: new credential produced"]);
    expect(body.proposal.expiresInDays).toBe(7);
    expect(fixture.env.logs.join("\n")).toContain(
      "value: 17 bytes, 1 line (the current value: 17 bytes, 1 line; the shape is shown here and at the acceptance only; it is not stored with the proposal)",
    );
    expect(body.proposal.variables).toHaveLength(1);
    const variable = nth(body.proposal.variables, 0);
    expect(variable).toMatchObject({ variableId: "vs", baseVersion: 3 });
    // W(E): the member's device and both of the owner's devices with an
    // effective role of member or above — not the reader, and not the
    // owner's reader-capped device (it could open the value but never push it)
    const ownerDevices = ownerDevicesInOrder();
    expect(variable.wraps.map((wrap) => wrap.recipientUserId)).toEqual([
      member.userId,
      owner.userId,
      owner.userId,
    ]);
    expect(variable.wraps.map((wrap) => wrap.recipientEncPubHex)).toEqual([
      member.encPubHex,
      ...ownerDevices.map((device) => device.encPubHex),
    ]);
    expect(variable.wraps.map((wrap) => wrap.recipientEncPubHex)).not.toContain(
      ownerReaderCap.encPubHex,
    );
    const [memberWrap, ...ownerWraps] = variable.wraps;
    expect(ownerWraps).toHaveLength(2);
    if (memberWrap === undefined) {
      throw new Error("no member wrap");
    }
    expect(await openWith(member.encKeyPair, member.userId, body, memberWrap)).toBe(NEW_KEY);
    expect(await openedByOwnerDevices(body, ownerWraps)).toEqual([NEW_KEY, NEW_KEY]);
    // Crosswise opening fails (one Seal per device)
    expect(await openWith(reader.encKeyPair, reader.userId, body, memberWrap)).toBeNull();

    const logs = fixture.env.logs.join("\n");
    expect(logs).toContain(
      `Sealed proposal ${body.proposal.proposalId} stored for environment prod`,
    );
    expect(logs).toContain("STRIPE_SECRET_KEY (replacing version 3)");
    expect(logs).toContain("sealed to 3 devices of 2 members");
    expect(logs).toContain(`maruhi rotation accept ${body.proposal.proposalId}`);
    expectNoSecretLeak(fixture);
  });

  it("a JSON-answer rule proposes the companion first, each variable against its own leased version, and --expires-in sets the expiry", async () => {
    const fixture = await startCi({
      version: 1,
      variables: {
        STRIPE_SECRET_KEY: {
          connector: "exec",
          rotate: ["./rotate.sh"],
          finalize: ["./finalize.sh"],
          output: "json",
          companions: { STRIPE_KEY_ID: "STRIPE_KEY_ID" },
        },
      },
    });
    fixture.env.setCaptureHandler(() => ({
      exitCode: 0,
      stdout: new TextEncoder().encode(
        JSON.stringify({
          value: NEW_KEY,
          companions: { STRIPE_KEY_ID: NEW_ID },
          facts: [`created key ${NEW_ID} at stripe`],
        }),
      ),
      stderr: "",
    }));
    const before = Date.now();
    expect(await ciRotate(fixture, "--expires-in", "30")).toBe(0);
    const body = fixture.minted.bodies[0];
    expect(body).toBeDefined();
    if (body === undefined) {
      return;
    }
    // Companions first (the server stores this order; accept pushes in it)
    expect(body.proposal.variables.map((variable) => variable.variableId)).toEqual(["vk", "vs"]);
    expect(body.proposal.variables.map((variable) => variable.baseVersion)).toEqual([1, 3]);
    const [idVariable, keyVariable] = body.proposal.variables;
    const idWrap = idVariable?.wraps.find((wrap) => wrap.recipientEncPubHex === member.encPubHex);
    const keyWrap = keyVariable?.wraps.find((wrap) => wrap.recipientEncPubHex === member.encPubHex);
    expect(idWrap).toBeDefined();
    expect(keyWrap).toBeDefined();
    if (idWrap === undefined || keyWrap === undefined) {
      return;
    }
    expect(
      await openWith(member.encKeyPair, member.userId, body, idWrap, {
        variableId: "vk",
        baseVersion: 1,
      }),
    ).toBe(NEW_ID);
    expect(await openWith(member.encKeyPair, member.userId, body, keyWrap)).toBe(NEW_KEY);
    // The script's fact is scrubbed of the produced values
    expect(body.proposal.facts).toEqual([
      "./rotate.sh: new credential produced (created key [redacted] at stripe)",
    ]);
    // Both variables were pre-flighted, in push order
    expect(fixture.preflighted.bodies[0]?.variables).toEqual([
      { variableId: "vk", baseVersion: 1 },
      { variableId: "vs", baseVersion: 3 },
    ]);
    // The lifetime travels as days; the report shows the server's instant
    expect(body.proposal.expiresInDays).toBe(30);
    const thirtyDays = 30 * 24 * 60 * 60 * 1000;
    const logs = fixture.env.logs.join("\n");
    expect(logs).toContain(
      "STRIPE_KEY_ID (replacing version 1), STRIPE_SECRET_KEY (replacing version 3)",
    );
    const expiresLine = logs.match(/expires (\d{4}-\d{2}-\d{2})/)?.[1];
    expect(expiresLine).toBe(new Date(before + thirtyDays).toISOString().slice(0, 10));
    expectNoSecretLeak(fixture);
  });

  it("re-leases and re-seals once when the recipients changed between the lease and the mint", async () => {
    // The tokens carry an expiry (as GitHub's do): the re-lease presents
    // the newest token the job holds for the lease's key while it is
    // unexpired. The issuance endpoint stops answering after the mint's
    // token (jti 2): the recovery still goes through on that token (O-15)
    const first = await realNowClock();
    const fixture = await startCi(EXEC_RULE, {
      expSeconds: Math.floor(first.nowMs / 1000) + 600,
      failAfter: 2,
    });
    fixture.minted.rejectOnce = {
      status: 422,
      json: { _tag: "RotationProposalRejected", reason: "recipients-mismatch" },
    };
    expect(await ciRotateOnClock(fixture, first.clock)).toBe(0);
    // One connector run, two leases, two mints under distinct proposal ids
    expect(fixture.env.captureCalls).toHaveLength(1);
    expect(fixture.leased.bodies).toHaveLength(2);
    expect(fixture.minted.bodies).toHaveLength(2);
    // The re-lease presents the mint's token (jti 2 — the newest) under the
    // lease's key (AUTH_SPEC §14-1's idempotent re-claim; O-13 / O-15), and
    // the second mint falls back to it as well (the endpoint is down)
    expect(jtiOf(nth(fixture.leased.bodies, 0))).toBe(1);
    expect(jtiOf(nth(fixture.leased.bodies, 1))).toBe(2);
    expect(nth(fixture.leased.bodies, 1).ephemeralPubHex).toBe(
      nth(fixture.leased.bodies, 0).ephemeralPubHex,
    );
    expect(jtiOf(nth(fixture.minted.bodies, 1))).toBe(2);
    expect(nth(fixture.minted.bodies, 0).proposal.proposalId).not.toBe(
      nth(fixture.minted.bodies, 1).proposal.proposalId,
    );
    expect(fixture.env.errors).toEqual(
      expect.arrayContaining([
        "The project's members or devices changed after this job leased it: leasing again and sealing the proposal to the current recipients (once)",
      ]),
    );
    expect(fixture.env.logs).toEqual(
      expect.arrayContaining([
        "The proposal was sealed a second time: the members or devices changed after the lease, so the recipients were taken from the current chain",
      ]),
    );
    // A token within the reuse margin of its expiry is still presented
    // when no fresh one can be minted (O-17): the re-lease goes through
    const second = await realNowClock();
    const nearExpiry = await startCi(EXEC_RULE, {
      expSeconds: Math.floor(second.nowMs / 1000) + 20,
      failAfter: 2,
    });
    nearExpiry.minted.rejectOnce = {
      status: 422,
      json: { _tag: "RotationProposalRejected", reason: "recipients-mismatch" },
    };
    expect(await ciRotateOnClock(nearExpiry, second.clock)).toBe(0);
    expect(nearExpiry.leased.bodies).toHaveLength(2);
    expect(jtiOf(nth(nearExpiry.leased.bodies, 1))).toBe(2);
    expect(nearExpiry.env.errors.join("\n")).toContain(
      "Could not mint a fresh OIDC token for the lease",
    );
    // A second mismatch is the recovery message, not a loop
    const twice = await startCi();
    twice.minted.reject = {
      status: 422,
      json: { _tag: "RotationProposalRejected", reason: "recipients-mismatch" },
    };
    expect(await ciRotate(twice)).toBe(1);
    expect(twice.minted.bodies).toHaveLength(2);
    expect(twice.env.errors).toEqual(
      expect.arrayContaining([
        "maruhi: The issuer accepted the rotation (./rotate.sh: new credential produced) but the server refused to store the proposal: the project's members or devices changed after this job leased it. Re-run the job. Recovery for the credential that now exists at the issuer: the new credential is held only by this process (it is not shown) — re-run the rotation (./rotate.sh runs again; make it idempotent, or retire the unused credential at the issuer by hand)",
      ]),
    );
    expectNoSecretLeak(fixture);
  });

  it("a hung issuance endpoint does not eat the fallback: the fetch's bound follows the life of the token in hand (O-18)", async () => {
    // The lease token lives ~10 s; the mint's fetch hangs, so its bound is
    // the token's remaining life minus the margin, and the lease's token is
    // presented while it still lives. The clock runs past the bound (~8 s)
    // while staying under the expiry, so the recovery keeps a live token.
    const { clock, nowMs } = await realNowClock();
    const fixture = await startCi(EXEC_RULE, {
      expSeconds: Math.floor(nowMs / 1000) + 10,
      hangAfter: 1,
    });
    const run = ciRotateOnClock(fixture, clock);
    // The mint's fetch is in flight with its bound taken before the hang
    await oidcFetches(fixture, 2);
    await clockAdjust(clock, 8_500);
    expect(await run).toBe(0);
    const body = onlyMint(fixture);
    expect(jwtPayload(body.oidcToken)["jti"]).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("presenting the lease's token");
  }, 20_000);

  it("an expired lease token does not shorten the fetch of a fresh one: a slow issuance endpoint still mints (O-19)", async () => {
    // The lease's token is already expired, so there is no fallback to
    // protect: the mint's fetch gets the default bound (30 s), not the
    // floor, and the endpoint's late answer (3 s real) is waited for. The
    // clock crosses a 1 s floor bound while the fetch is in flight, so a
    // shortened bound would fail the run where the default does not.
    const { clock, nowMs } = await realNowClock();
    const fixture = await startCi(EXEC_RULE, {
      expSeconds: Math.floor(nowMs / 1000) - 60,
      delayAfter: 1,
    });
    const run = ciRotateOnClock(fixture, clock);
    await oidcFetches(fixture, 2);
    await clockAdjust(clock, 2_000);
    expect(await run).toBe(0);
    const body = onlyMint(fixture);
    expect(jwtPayload(body.oidcToken)["jti"]).toBe(2);
    expect(fixture.env.errors.join("\n")).not.toContain("presenting the lease's token");
    expectNoSecretLeak(fixture);
  }, 20_000);

  it("the issuance bound follows the token in hand: capped at the default, the remaining life minus the margin, the default again when the token cannot outlive the floor (O-18 / O-19)", () => {
    const now = 1_700_000_000_000;
    const tokenWith = (exp?: number) =>
      Redacted.make(
        fakeJwt({ iss: ISSUER, sub: "x", aud: "y", ...(exp === undefined ? {} : { exp }) }),
      );
    const bound = (secondsLeft?: number) =>
      issuanceBoundFor(
        tokenWith(secondsLeft === undefined ? undefined : Math.floor(now / 1000) + secondsLeft),
        now,
      );
    expect(bound()).toBe(30_000);
    expect(bound(600)).toBe(30_000);
    expect(bound(8)).toBe(6000);
    expect(bound(3.5)).toBe(1500);
    // Less than the margin plus the floor left: no fallback to protect
    expect(bound(2.5)).toBe(30_000);
    expect(bound(-60)).toBe(30_000);
  });

  it("an expired lease token is not presented when no fresh token can be minted: the recovery step is named", async () => {
    const { clock, nowMs } = await realNowClock();
    const fixture = await startCi(EXEC_RULE, {
      expSeconds: Math.floor(nowMs / 1000) - 60,
      failAfter: 1,
    });
    expect(await ciRotateOnClock(fixture, clock)).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "no token is left to store the proposal: the lease's token expired at",
    );
    expect(errors).toContain("before a fresh one could be minted (");
    expect(errors).toContain("Recovery for the credential that now exists at the issuer");
    expect(fixture.minted.bodies).toHaveLength(0);
    expectNoSecretLeak(fixture);
  });

  it("a lease token dead on the run's clock is abandoned even while real time says it lives (mutation sentinel)", async () => {
    // The run's clock sits a minute ahead of real time, so a token with
    // 30 s of real life left is already dead to it — reverting the
    // catch's clock read (or both reads) to Date.now() sees a live
    // token, takes the fallback and exits 0, so this case fails green
    // on that revert
    const { clock, nowMs } = await realNowClock();
    await clockAdjust(clock, 60_000);
    const fixture = await startCi(EXEC_RULE, {
      expSeconds: Math.floor(nowMs / 1000) + 30,
      failAfter: 1,
    });
    expect(await ciRotateOnClock(fixture, clock)).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "no token is left to store the proposal: the lease's token expired at",
    );
    expect(fixture.minted.bodies).toHaveLength(0);
    expectNoSecretLeak(fixture);
  });

  it("refuses a rule without a grace period before touching the issuer (a proposal can be rejected or expire)", async () => {
    const fixture = await startCi({
      version: 1,
      variables: { STRIPE_SECRET_KEY: { connector: "exec", rotate: ["./rotate.sh"] } },
    });
    expect(await ciRotate(fixture)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "Refusing to propose a rotation of STRIPE_SECRET_KEY from CI: this rule's rotation invalidates the current credential at once",
    );
    expect(fixture.env.captureCalls).toHaveLength(0);
    expect(fixture.minted.bodies).toHaveLength(0);
    expectNoSecretLeak(fixture);
  });

  it("the pre-flight refuses a pending or stale variable, or a project at the storage guard, before the issuer is touched", async () => {
    const fixture = await startCi();
    fixture.preflighted.reject = {
      status: 422,
      json: { _tag: "RotationProposalRejected", reason: "variable-pending" },
    };
    expect(await ciRotate(fixture)).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "Refusing to rotate STRIPE_SECRET_KEY from CI: the server would not store the proposal (a sealed proposal for one of its variables is already pending)",
    );
    expect(errors).toContain("Nothing was sent to the issuer");
    expect(errors).not.toContain("Recovery");
    expect(fixture.env.captureCalls).toHaveLength(0);
    expect(fixture.minted.bodies).toHaveLength(0);
    // Only the lease's token was minted (no fresh token for a mint that never happened)
    expect(fixture.preflighted.bodies).toHaveLength(1);
    const stale = await startCi();
    stale.preflighted.reject = {
      status: 422,
      json: { _tag: "RotationProposalRejected", reason: "base-version-stale" },
    };
    expect(await ciRotate(stale)).toBe(1);
    expect(stale.env.errors.join("\n")).toContain(
      "a member pushed the variable after this job leased it",
    );
    expect(stale.env.captureCalls).toHaveLength(0);
    const full = await startCi();
    full.preflighted.reject = {
      status: 422,
      json: { _tag: "RotationProposalRejected", reason: "storage-limit" },
    };
    expect(await ciRotate(full)).toBe(1);
    expect(full.env.errors.join("\n")).toContain(
      "the project's stored data has reached the server's storage guard (AUTH_SPEC §12-8)",
    );
    expect(full.env.captureCalls).toHaveLength(0);
    expect(full.minted.bodies).toHaveLength(0);
    expectNoSecretLeak(fixture);
  });

  it("names the recovery step when the server refuses the proposal after the issuer accepted the rotation", async () => {
    const fixture = await startCi();
    fixture.minted.reject = {
      status: 422,
      json: { _tag: "RotationProposalRejected", reason: "base-version-stale" },
    };
    expect(await ciRotate(fixture)).toBe(1);
    expect(fixture.env.errors).toEqual(
      expect.arrayContaining([
        "maruhi: The issuer accepted the rotation (./rotate.sh: new credential produced) but the server refused to store the proposal: a member pushed the variable after this job leased it. Re-run the job once the members are done. Recovery for the credential that now exists at the issuer: the new credential is held only by this process (it is not shown) — re-run the rotation (./rotate.sh runs again; make it idempotent, or retire the unused credential at the issuer by hand)",
      ]),
    );
    expectNoSecretLeak(fixture);
    // The storage guard can be crossed between the pre-flight and the mint
    const full = await startCi();
    full.minted.reject = {
      status: 422,
      json: { _tag: "RotationProposalRejected", reason: "storage-limit" },
    };
    expect(await ciRotate(full)).toBe(1);
    const errors = full.env.errors.join("\n");
    expect(errors).toContain("the project's stored data has reached the server's storage guard");
    expect(errors).toContain("Recovery for the credential that now exists at the issuer");
    expectNoSecretLeak(full);
  });

  it("surfaces the crypto layer's InvalidInput verbatim when the new value exceeds the sealed-value bound", async () => {
    // The connector emits a >64KiB value: sealProposedValue refuses it
    // (MAX_SEALED_VALUE_BYTES), and the proposal-refusal path folds the seal
    // failure's message into the recovery notice
    const fixture = await startCi();
    fixture.env.setCaptureHandler(() => ({
      exitCode: 0,
      stdout: new TextEncoder().encode("x".repeat(64 * 1024)),
      stderr: "",
    }));
    expect(await ciRotate(fixture)).toBe(1);
    expect(fixture.env.errors).toEqual(
      expect.arrayContaining([
        `maruhi: The issuer accepted the rotation (./rotate.sh: new credential produced) but the server refused to store the proposal: Sealing the new value of vs to member user-member-2222 failed (InvalidInput). Re-run the job. Recovery for the credential that now exists at the issuer: the new credential is held only by this process (it is not shown) — re-run the rotation (./rotate.sh runs again; make it idempotent, or retire the unused credential at the issuer by hand)`,
      ]),
    );
    expect(fixture.minted.bodies).toHaveLength(0);
    expectNoSecretLeak(fixture);
  });

  it("missing flags are usage errors (2) before any network", async () => {
    const fixture = await startCi();
    expect(
      await runCli(
        ["ci", "rotate", "STRIPE_SECRET_KEY", "--server", fixture.server.origin],
        fixture.env.layer,
      ),
    ).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain("ci rotate requires --project");
    expect(
      await runCli(
        [
          "ci",
          "rotate",
          "STRIPE_SECRET_KEY",
          "--server",
          fixture.server.origin,
          "--project",
          built.projectId,
          "--env",
          ENV_ID,
          "--rotate-config",
          fixture.configPath,
          "--expires-in",
          "45",
        ],
        fixture.env.layer,
      ),
    ).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain(
      "--expires-in must be a number of days from 1 to 30",
    );
    expect(fixture.leased.bodies).toHaveLength(0);
    expect(fixture.minted.bodies).toHaveLength(0);
  });
});
