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
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { OIDC_REQUEST_TOKEN_ENV, OIDC_REQUEST_URL_ENV } from "../src/oidc-github.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
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
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer } from "./support/server.ts";

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

function oidcHandler(state: { issued: number }): MockHandler {
  return (request) => {
    if (request.method !== "GET" || request.path !== "/oidc/token") {
      return null;
    }
    if (request.headers["authorization"] !== `Bearer ${RUNNER_TOKEN}`) {
      return { status: 401, json: { message: "bad runner token" } };
    }
    state.issued += 1;
    return {
      status: 200,
      json: {
        value: fakeJwt({
          iss: ISSUER,
          sub: `repo:acme/app:ref:refs/heads/main/run/${state.issued}`,
          aud: request.query["audience"] ?? "",
          jti: state.issued,
        }),
      },
    };
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
      projectId: built.projectId,
      environmentId: ENV_ID,
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
    readonly expiresAtMs: number;
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
    return {
      status: 200,
      json: { proposalId: body.proposal.proposalId, expiresAtMs: body.proposal.expiresAtMs },
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

interface CiFixture {
  readonly env: TestEnv;
  readonly server: MockServer;
  readonly configPath: string;
  readonly leased: Leased;
  readonly minted: Minted;
}

/** CI environment: neither login nor config is seeded (CI mode's independence is pinned by this setup). */
async function startCi(config: unknown = EXEC_RULE): Promise<CiFixture> {
  const leased: Leased = { bodies: [] };
  const minted: Minted = { requests: [], bodies: [] };
  const server = await MockServer.start([
    oidcHandler({ issued: 0 }),
    leaseHandler(leased),
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
  return { env, server, configPath, leased, minted };
}

function ciRotate(fixture: CiFixture, ...extra: string[]): Promise<number> {
  return runCli(
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
      ...extra,
    ],
    fixture.env.layer,
  );
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
      projectId: built.projectId,
      environmentId: ENV_ID,
      proposalId: body.proposal.proposalId,
      variableId: target.variableId,
      baseVersion: target.baseVersion,
      recipientUserId: userId,
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

describe("maruhi ci rotate (sealed value proposals — PF7b)", () => {
  it("runs the connector from the lease and stores the new value sealed to every member device in scope, under the lease's token and key", async () => {
    const fixture = await startCi();
    expect(await ciRotate(fixture)).toBe(0);

    // The script saw the leased credential and admin input (memory only)
    expect(fixture.env.captureCalls).toHaveLength(1);
    const call = fixture.env.captureCalls[0];
    expect(call?.command).toEqual(["./rotate.sh"]);
    expect(call?.extraEnv["STRIPE_SECRET_KEY"]).toBe(OLD_KEY);
    expect(call?.extraEnv["STRIPE_ADMIN_KEY"]).toBe(ADMIN_KEY);
    expect(call?.extraEnv["MH_ROTATE_PHASE"]).toBe("rotate");

    // One mint, under the same token and ephemeral key as the lease (§14-5)
    expect(fixture.minted.bodies).toHaveLength(1);
    const body = fixture.minted.bodies[0];
    expect(body).toBeDefined();
    if (body === undefined) {
      return;
    }
    expect(fixture.leased.bodies).toHaveLength(1);
    expect(body.oidcToken).toBe(fixture.leased.bodies[0]?.oidcToken);
    expect(body.ephemeralPubHex).toBe(fixture.leased.bodies[0]?.ephemeralPubHex);
    expect(body.proposal.proposalId).toMatch(/^[0-9a-f]{32}$/);
    expect(body.proposal.connector).toBe("exec");
    expect(body.proposal.facts).toEqual(["./rotate.sh: new credential produced"]);
    expect(body.proposal.variables).toHaveLength(1);
    const variable = body.proposal.variables[0];
    expect(variable).toMatchObject({ variableId: "vs", baseVersion: 3 });
    // W(E): the member's device and both of the owner's devices with an
    // effective role of member or above — not the reader, and not the
    // owner's reader-capped device (it could open the value but never push it)
    const ownerDevices = ownerDevicesInOrder();
    expect(variable?.wraps.map((wrap) => wrap.recipientUserId)).toEqual([
      member.userId,
      owner.userId,
      owner.userId,
    ]);
    expect(variable?.wraps.map((wrap) => wrap.recipientEncPubHex)).toEqual([
      member.encPubHex,
      ...ownerDevices.map((device) => device.encPubHex),
    ]);
    expect(variable?.wraps.map((wrap) => wrap.recipientEncPubHex)).not.toContain(
      ownerReaderCap.encPubHex,
    );
    const [memberWrap, ...ownerWraps] = variable?.wraps ?? [];
    expect(memberWrap).toBeDefined();
    expect(ownerWraps).toHaveLength(2);
    if (memberWrap === undefined) {
      return;
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
    const thirtyDays = 30 * 24 * 60 * 60 * 1000;
    expect(body.proposal.expiresAtMs).toBeGreaterThanOrEqual(before + thirtyDays);
    expect(body.proposal.expiresAtMs).toBeLessThanOrEqual(Date.now() + thirtyDays);
    expect(fixture.env.logs.join("\n")).toContain(
      "STRIPE_KEY_ID (replacing version 1), STRIPE_SECRET_KEY (replacing version 3)",
    );
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

  it("names the recovery step when the server refuses the proposal after the issuer accepted the rotation", async () => {
    const fixture = await startCi();
    fixture.minted.reject = {
      status: 422,
      json: { _tag: "RotationProposalRejected", reason: "base-version-stale" },
    };
    expect(await ciRotate(fixture)).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("The issuer accepted the rotation");
    expect(errors).toContain("a member pushed the variable after this job leased it");
    expect(errors).toContain("Recovery for the credential that now exists at the issuer");
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
