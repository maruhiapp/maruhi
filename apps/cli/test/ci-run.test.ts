import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ChainEntry, LeaseClaims } from "@maruhi/crypto";
import {
  computeLeaseClaimsDigest,
  encodeHex,
  importEncryptionPublicKey,
  wrapLeaseDek,
} from "@maruhi/crypto";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  deleteEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedValue,
  distributedVariableStatement,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes,
  revokeServerOp,
  rotateEpochOp,
  testEnvironmentId,
  testProjectId,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
} from "@maruhi/test-kit";
import type { ApiSuccess } from "@maruhi/test-kit/api";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { OIDC_REQUEST_TOKEN_ENV, OIDC_REQUEST_URL_ENV } from "../src/oidc-github.ts";
import { lastHashOf, servedChain } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import {
  type EndpointAnswer,
  type MockHandler,
  type MockRequest,
  MockServer,
  offSpec,
  onEndpoint,
} from "./support/server.ts";

const ENV_ID = "prod";
const ISSUER = "https://token.actions.githubusercontent.com";
const SUBJECT = "repo:acme/app:ref:refs/heads/main";
const RUNNER_TOKEN = "runner-request-token-value";
const OTHER_ENV_ID = "staging";
const UNGRANTED_SEQ = 3;
const OTHER_SCOPE_SEQ = 5;
const GRANTED_SEQ = 6;
const REVOKED_SEQ = 7;
const DELETED_SEQ = 8;

function chainPrefixOf(chain: BuiltChain, seq: number): BuiltChain {
  return {
    projectId: chain.projectId,
    entries: chain.entries.slice(0, seq),
    hashes: chain.hashes.slice(0, seq),
  };
}

interface PullEntry {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

interface Fixture {
  readonly owner: GeneratedIdentity;
  readonly built: BuiltChain;
  readonly extended: BuiltChain;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly entryAlpha: PullEntry;
  readonly entryBeta: PullEntry;
}

let fixture: Fixture;
let servers: MockServer[] = [];

beforeAll(async () => {
  const owner = await generateIdentity("user-owner-1111");
  const dek1 = crypto.getRandomValues(new Uint8Array(32));
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  const leasePolicy = [
    { issuerUrl: ISSUER, audience: "https://maruhi.example", claimConstraints: [] },
  ];
  const grantA = await grantServerOp([ENV_ID], leasePolicy);
  if (grantA.op !== "grant_server") {
    throw new Error("grantServerOp built another operation");
  }
  const extended = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    { actor: owner, operation: createEnvironmentOp(OTHER_ENV_ID, dek1) },
    { actor: owner, operation: await grantServerOp([OTHER_ENV_ID], leasePolicy) },
    { actor: owner, operation: grantA },
    { actor: owner, operation: revokeServerOp(grantA.payload.serverKeyFingerprintHex) },
    { actor: owner, operation: deleteEnvironmentOp(ENV_ID) },
  ]);
  const built = chainPrefixOf(extended, GRANTED_SEQ);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const valueAlpha = await distributedValue({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 3,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(built, 3),
  });
  const valueBeta = await distributedValue({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "vb",
    version: 1,
    plaintext: "beta-value",
    writer: owner,
    head: headOf(built, 2),
  });
  const genesisHead = { seq: 1, hashHex: built.projectId };
  const envStatement = await distributedEnvironmentStatement({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: genesisHead,
  });
  const entryAlpha = {
    variableId: "va",
    statement: await distributedVariableStatement({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "va",
      name: "ALPHA",
      author: owner,
      head: genesisHead,
    }),
    value: valueAlpha,
  };
  const entryBeta = {
    variableId: "vb",
    statement: await distributedVariableStatement({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vb",
      name: "BETA",
      author: owner,
      head: genesisHead,
    }),
    value: valueBeta,
  };
  fixture = { owner, built, extended, dek1, dek2, envStatement, entryAlpha, entryBeta };
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
  const segment = token.split(".")[1];
  if (segment === undefined) {
    throw new Error("not a compact JWS");
  }
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;
}

interface OidcIssuance {
  readonly audiences: string[];
  issued: number;
}

function oidcHandler(state: OidcIssuance): MockHandler {
  return (request) => {
    if (request.method !== "GET" || request.path !== "/oidc/token") {
      return null;
    }
    if (request.headers["authorization"] !== `Bearer ${RUNNER_TOKEN}`) {
      return { status: 401, json: { message: "bad runner token" } };
    }
    const audience = request.query["audience"] ?? "";
    state.audiences.push(audience);
    state.issued += 1;
    return {
      status: 200,
      json: {
        value: fakeJwt({
          iss: ISSUER,
          sub: `${SUBJECT}/run/${state.issued}`,
          aud: audience,
          jti: state.issued,
        }),
      },
    };
  };
}

interface LeaseResponseOverrides {
  readonly claims?: Partial<LeaseClaims>;
  readonly dekForEpoch?: (epoch: number, dek: Uint8Array) => Uint8Array;
  readonly entries?: readonly ChainEntry[];
  readonly headHashHex?: string;
  readonly garbageLeases?: boolean;
  readonly declaredProjectId?: string;
  readonly currentEpoch?: number;
  readonly variables?: readonly PullEntry[];
  readonly declaredVariables?: readonly WireDistributedVariableStatement[];
  readonly extraLeases?: readonly { readonly epoch: number; readonly dek: Uint8Array }[];
}

async function leaseClaimsDigestOf(
  oidcToken: string,
  overrides?: LeaseResponseOverrides,
): Promise<string> {
  const payload = jwtPayload(oidcToken);
  const digest = await computeLeaseClaimsDigest({
    issuerUrl: overrides?.claims?.issuerUrl ?? String(payload["iss"]),
    subject: overrides?.claims?.subject ?? String(payload["sub"]),
    audience: overrides?.claims?.audience ?? String(payload["aud"]),
  });
  if (!digest.ok) {
    throw new Error("claims digest failed");
  }
  return digest.value;
}

async function leaseWrapFor(input: {
  readonly ephemeralPubHex: string;
  readonly claimsDigestHex: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
}): Promise<ApiSuccess<"lease.issue">["leases"][number]> {
  const publicKey = await importEncryptionPublicKey(hexBytes(input.ephemeralPubHex));
  if (!publicKey.ok) {
    throw new Error("ephemeral public key rejected");
  }
  const wrapped = await wrapLeaseDek({
    workloadPublicKey: publicKey.value,
    dek: input.dek,
    context: {
      projectId: testProjectId(fixture.built.projectId),
      environmentId: testEnvironmentId(ENV_ID),
      epoch: input.epoch,
      claimsDigestHex: input.claimsDigestHex,
    },
  });
  if (!wrapped.ok) {
    throw new Error("lease wrap failed");
  }
  return {
    suite: "maruhi/v1",
    epoch: input.epoch,
    encHex: encodeHex(wrapped.value.enc),
    ciphertextHex: encodeHex(wrapped.value.ciphertext),
  };
}

async function leaseResponseFor(
  body: { readonly oidcToken: string; readonly ephemeralPubHex: string },
  overrides?: LeaseResponseOverrides,
): Promise<ApiSuccess<"lease.issue">> {
  const { built, dek1, dek2, envStatement, entryAlpha, entryBeta } = fixture;
  const resolved = {
    declaredProjectId: built.projectId,
    currentEpoch: 2,
    entries: built.entries,
    variables: [entryAlpha, entryBeta] as readonly PullEntry[],
    declaredVariables: [] as readonly WireDistributedVariableStatement[],
    dekForEpoch: (_epoch: number, dek: Uint8Array) => dek,
    extraLeases: [] as readonly { readonly epoch: number; readonly dek: Uint8Array }[],
    ...overrides,
  };
  const claimsDigestHex = await leaseClaimsDigestOf(body.oidcToken, overrides);
  const wrapFor = (epoch: number, dek: Uint8Array) =>
    leaseWrapFor({
      ephemeralPubHex: body.ephemeralPubHex,
      claimsDigestHex,
      epoch,
      dek: resolved.dekForEpoch(epoch, dek),
    });
  return {
    projectId: resolved.declaredProjectId,
    environmentId: ENV_ID,
    currentEpoch: resolved.currentEpoch,
    chain: resolved.entries,
    headSeq: resolved.entries.length,
    headHashHex: overrides?.headHashHex ?? lastHashOf(built.hashes),
    statement: envStatement,
    variables: resolved.variables,
    deletedVariables: [],
    ...(resolved.declaredVariables.length === 0
      ? {}
      : { declaredVariables: resolved.declaredVariables }),
    manifest: await distributedManifest({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: resolved.currentEpoch,
      issuer: fixture.owner,
      head: headOf(built, resolved.currentEpoch === 1 ? 2 : 3),
      envStatement,
      statements: [
        ...resolved.variables.map((entry) => entry.statement),
        ...resolved.declaredVariables,
      ],
    }),
    leases:
      overrides?.garbageLeases === true
        ? [1, 2].map((epoch) => ({
            suite: "maruhi/v1",
            epoch,
            encHex: "ab".repeat(32),
            ciphertextHex: "cd".repeat(48),
          }))
        : [
            await wrapFor(1, dek1),
            await wrapFor(2, dek2),
            ...(await Promise.all(
              resolved.extraLeases.map((extra) => wrapFor(extra.epoch, extra.dek)),
            )),
          ],
  };
}

function leasePath(projectId?: string): string {
  return `/projects/${projectId ?? fixture.built.projectId}/environments/${ENV_ID}/lease`;
}

function leaseBody(request: MockRequest): { oidcToken: string; ephemeralPubHex: string } {
  return request.body as { oidcToken: string; ephemeralPubHex: string };
}

function leaseRouteOf(projectId?: string): {
  readonly projectId: string;
  readonly environmentId: string;
} {
  return { projectId: projectId ?? fixture.built.projectId, environmentId: ENV_ID };
}

function leaseHandler(overrides?: LeaseResponseOverrides, projectId?: string): MockHandler {
  return onEndpoint("lease.issue", leaseRouteOf(projectId), async (request) => ({
    status: 200,
    json: await leaseResponseFor(request.body, overrides),
  }));
}

function manifestlessLeaseHandler(): MockHandler {
  return onEndpoint("lease.issue", leaseRouteOf(), async (request) => {
    const { manifest: _suppressed, ...suppressingBody } = await leaseResponseFor(request.body);
    return offSpec({ status: 200, json: suppressingBody });
  });
}

interface CiEnv {
  readonly env: TestEnv;
  readonly server: MockServer;
  readonly oidc: OidcIssuance;
}

async function startCiEnv(handlers: readonly MockHandler[]): Promise<CiEnv> {
  const oidc: OidcIssuance = { audiences: [], issued: 0 };
  const server = await MockServer.start([oidcHandler(oidc), ...handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  env.setEnvVar(OIDC_REQUEST_URL_ENV, `${server.origin}/oidc/token?api-version=2`);
  env.setEnvVar(OIDC_REQUEST_TOKEN_ENV, RUNNER_TOKEN);
  return { env, server, oidc };
}

function ciArgs(server: MockServer, extra: readonly string[] = []): string[] {
  return [
    "ci",
    "run",
    "--server",
    server.origin,
    "--project",
    fixture.built.projectId,
    "--env",
    ENV_ID,
    ...extra,
    "--",
    "printenv",
    "ALPHA",
  ];
}

function expectNoSecretLeak(env: TestEnv): void {
  const output = [...env.logs, ...env.errors].join("\n");
  expect(output).not.toContain("alpha-value");
  expect(output).not.toContain("beta-value");
  expect(output).not.toContain(RUNNER_TOKEN);
  expect(output).not.toContain(base64UrlJson({ alg: "RS256", kid: "k1" }));
}

describe("maruhi ci run (happy path)", () => {
  it("verifies and decrypts with a single lease call, injecting into the child process env", async () => {
    const { env, server, oidc } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(0);

    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "ALPHA"]);
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe("alpha-value");
    expect(env.runnerCalls[0]?.extraEnv["BETA"]).toBe("beta-value");

    expect(server.requests.map((request) => request.path)).toEqual(["/oidc/token", leasePath()]);
    expect(oidc.audiences).toEqual([server.origin]);
    const sent = leaseBody(server.requests[1] as MockRequest);
    expect(sent.ephemeralPubHex).toMatch(/^[0-9a-f]{64}$/);

    expect(env.keychain.size).toBe(0);
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).toContain("Lease verified");
    expect(env.errors.join("\n")).toMatch(
      new RegExp(
        `^Note: project [0-9a-f]+ is disclosed to the server \\(CRYPTO_SPEC §9\\): server key [0-9a-f]{32} can decrypt the values of environment ${ENV_ID}$`,
        "mu",
      ),
    );
    expectNoSecretLeak(env);
  });

  it("--audience overrides the audience of the issuance request", async () => {
    const { env, server, oidc } = await startCiEnv([leaseHandler()]);
    const code = await runCli(ciArgs(server, ["--audience", "https://maruhi.example"]), env.layer);
    expect(code).toBe(0);
    expect(oidc.audiences).toEqual(["https://maruhi.example"]);
  });

  it("does not spawn the child process when a required = true declared is in the lease response (presence fail-fast — §1-4)", async () => {
    const declared = await distributedVariableStatement({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      variableId: "v-required",
      name: "MUST_HAVE",
      author: fixture.owner,
      head: { seq: 1, hashHex: fixture.built.projectId },
      status: "declared",
      schema: { varType: "string", required: true, description: "internal note" },
    });
    const { env, server } = await startCiEnv([leaseHandler({ declaredVariables: [declared] })]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.runnerCalls).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Required variables are declared but have no value yet");
    expect(errors).toContain("MUST_HAVE");
    expect(errors).not.toContain("internal note");
    expectNoSecretLeak(env);
  });

  it("runs with only an informational display when a required = false declared is present", async () => {
    const declared = await distributedVariableStatement({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      variableId: "v-optional",
      name: "NICE_TO_HAVE",
      author: fixture.owner,
      head: { seq: 1, hashHex: fixture.built.projectId },
      status: "declared",
      schema: { varType: "", required: false, description: "" },
    });
    const { env, server } = await startCiEnv([leaseHandler({ declaredVariables: [declared] })]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.extraEnv).not.toHaveProperty("NICE_TO_HAVE");
    expect(env.errors.join("\n")).toContain("declared variables without values were not injected");
  });
});

describe("maruhi ci run (verification-duty negative cases — CRYPTO_SPEC §9.1)", () => {
  it("(1) rejects a tampered chain (signature verification)", async () => {
    const entries = fixture.built.entries.map((entry, index) =>
      index === 1 ? ({ ...entry, timestampMs: entry.timestampMs + 1 } as ChainEntry) : entry,
    );
    const { env, server } = await startCiEnv([leaseHandler({ entries })]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Chain verification failed");
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("(1) rejects a distribution whose genesis does not match the pinned projectId", async () => {
    const pinned = "22".repeat(32);
    const { env, server } = await startCiEnv([leaseHandler({ declaredProjectId: pinned }, pinned)]);
    const args = [
      "ci",
      "run",
      "--server",
      server.origin,
      "--project",
      pinned,
      "--env",
      ENV_ID,
      "--",
      "printenv",
      "ALPHA",
    ];
    expect(await runCli(args, env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("genesis hash does not match the project ID");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("(3) rejects a commitment mismatch (poisoned wrap) and does not decrypt the value", async () => {
    const poison = crypto.getRandomValues(new Uint8Array(32));
    const { env, server } = await startCiEnv([
      leaseHandler({ dekForEpoch: (epoch, dek) => (epoch === 2 ? poison : dek) }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the commitment");
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("(4) rejects a bad value signature (substituted ciphertext)", async () => {
    const tampered: PullEntry = {
      ...fixture.entryAlpha,
      value: {
        ...fixture.entryAlpha.value,
        ciphertextHex: fixture.entryBeta.value.ciphertextHex,
      },
    };
    const { env, server } = await startCiEnv([
      leaseHandler({ variables: [tampered, fixture.entryBeta] }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("value signature");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("fails at unseal on a claims_digest mismatch (a wrap repurposed from another job context)", async () => {
    const { env, server } = await startCiEnv([
      leaseHandler({ claims: { subject: "repo:evil/other:ref:refs/heads/main" } }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("claims-digest mismatch");
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("rejects a response whose declared currentEpoch disagrees with the chain-derived one", async () => {
    const { env, server } = await startCiEnv([leaseHandler({ currentEpoch: 1 })]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("the chain derives epoch 2");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("(4) rejects immediately — without re-syncing — a value declaring a head beyond the bundled chain", async () => {
    const { built, owner, dek2 } = fixture;
    const futureValue = await distributedValue({
      dek: dek2,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 4,
      plaintext: "alpha-future",
      writer: owner,
      head: { seq: built.entries.length + 1, hashHex: "ee".repeat(32) },
    });
    const { env, server } = await startCiEnv([
      leaseHandler({
        variables: [{ ...fixture.entryAlpha, value: futureValue }, fixture.entryBeta],
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("beyond the chain included in the same response");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server.requests.map((request) => request.path)).toEqual(["/oidc/token", leasePath()]);
  });

  it("rejects duplicate lease wraps for the same epoch", async () => {
    const { env, server } = await startCiEnv([
      leaseHandler({ extraLeases: [{ epoch: 1, dek: fixture.dek1 }] }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Duplicate leased DEKs");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("rejects a lease wrap for an epoch beyond the chain-derived current epoch", async () => {
    const { env, server } = await startCiEnv([
      leaseHandler({
        extraLeases: [{ epoch: 3, dek: crypto.getRandomValues(new Uint8Array(32)) }],
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("beyond the chain's current epoch");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("reports the full refusal message on a claims-digest mismatch (a wrap repurposed from another job context)", async () => {
    const { env, server } = await startCiEnv([
      leaseHandler({ claims: { subject: "repo:evil/other:ref:refs/heads/main" } }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        "maruhi: Cannot open the leased DEK (epoch=1). The lease was issued for a different workload identity or context (claims-digest mismatch), or the response is corrupt",
      ]),
    );
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("reports the full refusal message for a leased DEK that fails the chain commitment (a fake-DEK injection)", async () => {
    const poison = crypto.getRandomValues(new Uint8Array(32));
    const { env, server } = await startCiEnv([
      leaseHandler({ dekForEpoch: (epoch, dek) => (epoch === 2 ? poison : dek) }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        "maruhi: The leased DEK does not match the commitment on the chain (epoch=2). This may be a fake DEK injected by a compromised server — do not trust this response",
      ]),
    );
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("(5) reports the full refusal message for a response without a manifest (manifest suppression — §6.3)", async () => {
    const { env, server } = await startCiEnv([manifestlessLeaseHandler()]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.at(-1)).toBe(
      "maruhi: The server did not distribute an environment manifest. A missing manifest is treated as manifest suppression (statement omission cannot be ruled out — CRYPTO_SPEC §6.3) and the response is rejected",
    );
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });
});

function chainPrefix(seq: number): LeaseResponseOverrides {
  const prefix = chainPrefixOf(fixture.extended, seq);
  return {
    entries: prefix.entries,
    headHashHex: prefix.hashes[prefix.hashes.length - 1] as string,
  };
}

function expectLeaseUnauthorized(env: TestEnv): void {
  const errors = env.errors.join("\n");
  expect(errors).toContain(
    `The server issued a lease for environment ${ENV_ID} of project ${fixture.built.projectId}, but the chain it sent carries no active grant_server naming that environment (CRYPTO_SPEC §9.1 (6))`,
  );
  expect(errors).toContain("The lease was not used");
  expect(errors).toContain("A conforming server answers 404 instead");
  expect(errors).toContain("Do not widen the grant");
  expect(errors).toContain("--anchor");
  expect(errors).not.toContain("Cannot open the leased DEK");
  expect(errors).not.toContain("Lease verified");
  expect(env.runnerCalls).toHaveLength(0);
  expectNoSecretLeak(env);
}

describe("maruhi ci run (lease authorization — CRYPTO_SPEC §9.1 (6))", () => {
  it("refuses a lease when the verified chain carries no grant at all", async () => {
    const { env, server } = await startCiEnv([leaseHandler(chainPrefix(UNGRANTED_SEQ))]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expectLeaseUnauthorized(env);
  });

  it("refuses a lease when the grant naming the environment was revoked", async () => {
    const { env, server } = await startCiEnv([leaseHandler(chainPrefix(REVOKED_SEQ))]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expectLeaseUnauthorized(env);
  });

  it("refuses a lease when the only active grant's scope does not name the environment", async () => {
    const { env, server } = await startCiEnv([leaseHandler(chainPrefix(OTHER_SCOPE_SEQ))]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expectLeaseUnauthorized(env);
  });

  it("refuses a deleted environment with the deletion message, ahead of the grant check", async () => {
    const { env, server } = await startCiEnv([leaseHandler(chainPrefix(DELETED_SEQ))]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Environment ${ENV_ID} is deleted (delete_environment at chain seq ${DELETED_SEQ})`,
    );
    expect(errors).not.toContain("CRYPTO_SPEC §9.1 (6)");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("opens no lease wrap on refusal (garbage wraps still yield the authorization error)", async () => {
    const { env, server } = await startCiEnv([
      leaseHandler({ ...chainPrefix(UNGRANTED_SEQ), garbageLeases: true }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expectLeaseUnauthorized(env);
  });

  it("garbage wraps under an authorizing chain fail at the unwrap (the probe of the case above)", async () => {
    const { env, server } = await startCiEnv([leaseHandler({ garbageLeases: true })]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Cannot open the leased DEK");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("accepts a lease covered by any active grant (the union — the other grant covers only staging)", async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    const notes = env.errors.filter((line) => line.includes("is disclosed to the server"));
    expect(notes).toHaveLength(2);
    expect(notes.some((line) => line.endsWith(`environment ${ENV_ID}`))).toBe(true);
    expect(notes.some((line) => line.endsWith(`environment ${OTHER_ENV_ID}`))).toBe(true);
  });

  it("with --anchor, a stale chain from before the revocation is refused (the anchor carries the head)", async () => {
    const revokedHead = chainPrefixOf(fixture.extended, REVOKED_SEQ);
    const path = await anchorFile({
      ...validAnchor(),
      headSeq: REVOKED_SEQ,
      headHashHex: revokedHead.hashes[REVOKED_SEQ - 1],
    });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain the anchored head");
    expect(env.runnerCalls).toHaveLength(0);
  });
});

function flakyLeaseHandler(failures: number, error: EndpointAnswer<"lease.issue">): MockHandler {
  let calls = 0;
  return onEndpoint("lease.issue", leaseRouteOf(), async (request) => {
    calls += 1;
    if (calls <= failures) {
      return error;
    }
    return { status: 200, json: await leaseResponseFor(request.body) };
  });
}

const TOKEN_REPLAYED: EndpointAnswer<"lease.issue"> = {
  status: 401,
  json: { _tag: "LeaseUnauthorized", reason: "token-replayed" },
};

describe("maruhi ci run (token-replayed / rate limit / 503)", () => {
  it("auto-retries token-replayed exactly once with a fresh token, presenting the same ephemeral key", async () => {
    const { env, server, oidc } = await startCiEnv([flakyLeaseHandler(1, TOKEN_REPLAYED)]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(0);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        "The lease was rejected as token-replayed (the token was already bound to a different ephemeral key). Minting a fresh token and retrying once",
      ]),
    );

    const leases = server.requests.filter((request) => request.path === leasePath());
    expect(leases).toHaveLength(2);
    const [first, second] = [
      leaseBody(leases[0] as MockRequest),
      leaseBody(leases[1] as MockRequest),
    ];
    expect(first.oidcToken).not.toBe(second.oidcToken);
    expect(first.ephemeralPubHex).toBe(second.ephemeralPubHex);
    expect(oidc.issued).toBe(2);
    expect(env.runnerCalls).toHaveLength(1);
  });

  it("stops after one retry if token-replayed persists with a fresh token (never sends a third)", async () => {
    const { env, server, oidc } = await startCiEnv([flakyLeaseHandler(99, TOKEN_REPLAYED)]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        "maruhi: The lease was rejected as token-replayed again with a freshly minted token. Someone else is using this job's OIDC tokens — investigate the job's steps and network path for token exfiltration (AUTH_SPEC §14-1)",
      ]),
    );
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(2);
    expect(oidc.issued).toBe(2);
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("does not retry non-token-replayed 401s and guides with the reason code", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 401,
        json: { _tag: "LeaseUnauthorized", reason: "unsupported-issuer" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        "maruhi: The OIDC token was rejected by the lease endpoint (unsupported-issuer). Check the token's issuer, audience, and validity window (AUTH_SPEC §14-1)",
      ]),
    );
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(1);
  });

  it("does not retry on 429; reports the remaining seconds and how to re-run", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 429,
        json: { _tag: "LeaseRateLimited", retryAfterSeconds: 1800, scope: "project-window" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("Retry after 1800 seconds");
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(1);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("guides that 503 oidc-jwks-unavailable is transient (not a credential problem)", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 503,
        json: { _tag: "LeaseUnavailable", reason: "oidc-jwks-unavailable" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("transient");
    expect(output).toContain("retry the job later");
    expect(output).not.toContain("Log in again");
  });

  it("guides 503 server-key-unconfigured toward setup as a missing deploy configuration", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 503,
        json: { _tag: "LeaseUnavailable", reason: "server-key-unconfigured" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("docs/SELF_HOSTING.md");
  });

  it("guides 503 server-wraps-missing toward admin rotation / backfill", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 503,
        json: { _tag: "LeaseUnavailable", reason: "server-wraps-missing" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("`maruhi env rotate` / `maruhi server grant`");
  });

  it("guides 503 SetupIncomplete rate-limit-unconfigured toward the deployment's rate-limit binding", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 503,
        json: { _tag: "SetupIncomplete", reason: "rate-limit-unconfigured" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("rate-limit-unconfigured");
    expect(output).toContain("bindings.rateLimit");
    expect(output).not.toContain("Log in again");
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(1);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("guides the fix target (coordinates / grant / policy) for 404, the uniform lease-specific response", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 404,
        json: { _tag: "ProjectNotFound", projectId: fixture.built.projectId },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        "maruhi: The server answered 404 for the lease. The lease endpoint folds these into one uniform answer (existence hiding — AUTH_SPEC §14-1): unknown project, no active grant, a lease-policy mismatch (issuer / audience / claim constraints), and an out-of-scope or unknown environment. Check --server, --project, and the environment in the workflow, and that a project owner granted this workload's identity with `maruhi server grant --lease-policy`",
      ]),
    );
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(1);
    expect(env.runnerCalls).toHaveLength(0);
  });
});

describe("maruhi ci run (OIDC issuance)", () => {
  it("names the id-token: write requirement before any communication when the issuance-endpoint env is absent", async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    env.setEnvVar(OIDC_REQUEST_URL_ENV, undefined);
    env.setEnvVar(OIDC_REQUEST_TOKEN_ENV, undefined);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("permissions: id-token: write");
    expect(server.requests).toHaveLength(0);
  });

  it("rejects a multi-aud token before the round trip (the claims digest would not be uniquely determined)", async () => {
    const { env, server } = await startCiEnv([
      (request) =>
        request.path === "/oidc/multi"
          ? {
              status: 200,
              json: { value: fakeJwt({ iss: ISSUER, sub: SUBJECT, aud: ["a", "b"] }) },
            }
          : null,
      leaseHandler(),
    ]);
    env.setEnvVar(OIDC_REQUEST_URL_ENV, `${server.origin}/oidc/multi`);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("multiple audiences");
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(0);
  });

  it("does not send the bearer token to a non-loopback http: issuance URL", async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    env.setEnvVar(OIDC_REQUEST_URL_ENV, "http://192.0.2.1/oidc/token");
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("ACTIONS_ID_TOKEN_REQUEST_URL is not a valid https:");
    expect(server.requests).toHaveLength(0);
  });

  it('does not treat a DNS name merely starting with "127." as loopback', async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    env.setEnvVar(OIDC_REQUEST_URL_ENV, "http://127.evil.com/oidc/token");
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("ACTIONS_ID_TOKEN_REQUEST_URL is not a valid https:");
    expect(server.requests).toHaveLength(0);
  });

  it("also rejects an unparsable issuance URL before any communication", async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    env.setEnvVar(OIDC_REQUEST_URL_ENV, "not a url");
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("ACTIONS_ID_TOKEN_REQUEST_URL is not a valid https:");
    expect(server.requests).toHaveLength(0);
  });

  it("does not follow redirects from the issuance endpoint (blocks bearer re-sends)", async () => {
    const { env, server } = await startCiEnv([
      (request) =>
        request.path.startsWith("/oidc/redirect")
          ? { status: 302, headers: { location: `${server.origin}/oidc/token` }, json: {} }
          : null,
      leaseHandler(),
    ]);
    env.setEnvVar(OIDC_REQUEST_URL_ENV, `${server.origin}/oidc/redirect`);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("HTTP 302");
    expect(
      server.requests.filter((request) => request.path.startsWith("/oidc/token")),
    ).toHaveLength(0);
  });
});

async function anchorFile(contents: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "maruhi-anchor-"));
  const path = join(dir, "maruhi-anchor.json");
  await writeFile(path, `${JSON.stringify(contents)}\n`);
  return path;
}

function validAnchor(): Record<string, unknown> {
  return {
    version: 1,
    projectId: fixture.built.projectId,
    headSeq: fixture.built.entries.length,
    headHashHex: lastHashOf(fixture.built.hashes),
    environments: { [ENV_ID]: 2 },
  };
}

describe("maruhi ci run --anchor (repository anchor — CRYPTO_SPEC §6.3 (b))", () => {
  it("succeeds with an anchor satisfying containment + non-regressing epoch", async () => {
    const path = await anchorFile(validAnchor());
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("repository anchor");
  });

  it("rejects a chain that does not contain the pinned head", async () => {
    const path = await anchorFile({ ...validAnchor(), headHashHex: "ab".repeat(32) });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain the anchored head");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("rejects an epoch regression below the anchor (distributing a pre-rotation view)", async () => {
    const path = await anchorFile({ ...validAnchor(), environments: { [ENV_ID]: 3 } });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("below the anchored epoch");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("rejects a pinned head whose seq exceeds the chain length (distribution of a stale view)", async () => {
    const path = await anchorFile({
      ...validAnchor(),
      headSeq: fixture.built.entries.length + 5,
    });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain the anchored head");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("rejects a distribution where the anchored environment is absent from the chain (rollback to before creation)", async () => {
    const path = await anchorFile({ ...validAnchor(), environments: { ghost: 1 } });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist on the distributed chain");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("fails a broken anchor file before any communication (with a path to regenerate it)", async () => {
    const path = await anchorFile({ version: 2 });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("maruhi project anchor");
    expect(server.requests).toHaveLength(0);
  });
});

describe("maruhi ci run (argument layer — ADR-0016)", () => {
  it("missing --server / --project / --env gets CI-specific fix guidance (exit 2)", async () => {
    for (const args of [
      ["ci", "run", "--", "true"],
      ["ci", "run", "--server", "https://maruhi.example", "--", "true"],
      [
        "ci",
        "run",
        "--server",
        "https://maruhi.example",
        "--project",
        "11".repeat(32),
        "--",
        "true",
      ],
    ]) {
      const env = await makeTestEnv();
      expect(await runCli(args, env.layer), args.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("CI mode reads no config file");
    }
  });

  it("checks the --project (genesis hash) and --env formats at their declarations, before the network", async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    const args = [
      "ci",
      "run",
      "--server",
      server.origin,
      "--project",
      "not-a-genesis",
      "--env",
      ENV_ID,
      "--",
      "true",
    ];
    expect(await runCli(args, env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "Unacceptable value for flag --project (expected: project id (lowercase hex SHA-256 of the genesis entry))",
    );

    const badEnv = await makeTestEnv();
    const badEnvArgs = [
      "ci",
      "run",
      "--server",
      server.origin,
      "--project",
      "11".repeat(32),
      "--env",
      "!bad",
      "--",
      "true",
    ];
    expect(await runCli(badEnvArgs, badEnv.layer)).toBe(2);
    expect(badEnv.errors.join("\n")).toContain(
      "Unacceptable value for flag --env (expected: environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric))",
    );
    expect(server.requests).toHaveLength(0);
  });

  it("a run without `--` / with no command to run is a usage error (exit 2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["ci", "run"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run");
  });
});

describe("maruhi project anchor", () => {
  it("prints anchor JSON to stdout from the verified view (in a form that passes ci run --anchor)", async () => {
    const { built, owner } = fixture;
    const server = await MockServer.start([
      onEndpoint("membership.get", { projectId: built.projectId }, () => ({
        status: 200,
        json: servedChain(built.projectId, built.entries, built.hashes),
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["project", "anchor"], env.layer)).toBe(0);
    const anchor: unknown = JSON.parse(env.logs.join("\n"));
    expect(anchor).toEqual({
      version: 1,
      projectId: built.projectId,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
      environments: { [ENV_ID]: 2, [OTHER_ENV_ID]: 1 },
    });

    const path = await anchorFile(anchor);
    const ci = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(ci.server, ["--anchor", path]), ci.env.layer)).toBe(0);
  });
});
