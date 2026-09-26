// Tests for `maruhi ci run` (CRYPTO_SPEC §9.1 / AUTH_SPEC §14).
//
// The lease endpoint is impersonated by MockServer (responses are built from real
// crypto fixtures, wrapLeaseDek'ing dynamically to the request's ephemeralPubHex).
// OIDC issuance is a separate MockServer path (signature is a dummy — the client
// does not verify), env reads are the test layer's setEnvVar. Server-side
// decisions are already pinned by apps/server/test/lease.test.ts; this file
// focuses on client behavior (§9.1 verification duties, retry discipline, error-category guidance).

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
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { OIDC_REQUEST_TOKEN_ENV, OIDC_REQUEST_URL_ENV } from "../src/oidc-github.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes,
  makeTestUser,
  manifestFor,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "prod";
const ISSUER = "https://token.actions.githubusercontent.com";
const SUBJECT = "repo:acme/app:ref:refs/heads/main";
const RUNNER_TOKEN = "runner-request-token-value";

interface PullEntry {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

interface Fixture {
  readonly owner: TestUser;
  readonly built: BuiltChain;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly entryAlpha: PullEntry;
  readonly entryBeta: PullEntry;
}

let fixture: Fixture;
let servers: MockServer[] = [];

beforeAll(async () => {
  const owner = await makeTestUser("user-owner-1111");
  const dek1 = crypto.getRandomValues(new Uint8Array(32));
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  // The chain carries a commitment to the real DEK and a grant_server (with the
  // lease policy) — the same shape as a production leased project (the client's
  // §9.1 verification does not inspect grant presence, but keep the fixture faithful)
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    {
      actor: owner,
      operation: await grantServerOp(
        [ENV_ID],
        [{ issuerUrl: ISSUER, audience: "https://maruhi.example", claimConstraints: [] }],
      ),
    },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  // The latest version's epoch differs per variable (same shape as §12-7):
  // ALPHA is epoch 2, BETA stays at epoch 1 — never re-encrypted after rotation
  const valueAlpha = await encryptValueFor({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 3,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(built, 3),
  });
  const valueBeta = await encryptValueFor({
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
  const envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: genesisHead,
  });
  const entryAlpha = {
    variableId: "va",
    statement: await statementFor({
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
    statement: await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vb",
      name: "BETA",
      author: owner,
      head: genesisHead,
    }),
    value: valueBeta,
  };
  fixture = { owner, built, dek1, dek2, envStatement, entryAlpha, entryBeta };
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/* -------------------------------------------------------------------------- */
/* Fixtures: OIDC issuance and lease responses                                 */
/* -------------------------------------------------------------------------- */

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/** Compact JWS with a dummy signature (the client does not verify it — §14-1). */
function fakeJwt(payload: Record<string, unknown>): string {
  return `${base64UrlJson({ alg: "RS256", kid: "k1" })}.${base64UrlJson(payload)}.c2lnbmF0dXJl`;
}

/** Same path as the server: read the claims from the presented token's payload. */
function jwtPayload(token: string): Record<string, unknown> {
  const segment = token.split(".")[1];
  if (segment === undefined) {
    throw new Error("not a compact JWS");
  }
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;
}

interface OidcIssuance {
  /** The audience specified in the issuance request (for inspection). */
  readonly audiences: string[];
  /** Number of tokens issued so far (embedded into jti — distinguishes tokens in the replay check). */
  issued: number;
}

/** Impersonation of the GitHub Actions OIDC issuance endpoint (returns `{ value }`). */
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
    // Vary sub per issuance: claims_digest binds only iss / sub / aud, so an
    // implementation that "reuses the old token's claims after retry" slips
    // through on a jti-only difference (the digest ends up identical). When sub
    // changes, only the correct implementation (computing the digest from the second token's claims) can unseal
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
  /** Substitutes the claims bound to the lease wrap (a wrap repurposed for another job context). */
  readonly claims?: Partial<LeaseClaims>;
  /** Substitutes the per-epoch DEK (poisoned wrap = commitment mismatch). */
  readonly dekForEpoch?: (epoch: number, dek: Uint8Array) => Uint8Array;
  readonly entries?: readonly ChainEntry[];
  readonly declaredProjectId?: string;
  readonly currentEpoch?: number;
  readonly variables?: readonly PullEntry[];
  /** Bundles the declared variables (§14-2 — material for ci run's presence check). */
  readonly declaredVariables?: readonly WireDistributedVariableStatement[];
  /** Extra lease wraps (for the negative cases: duplicate epochs and off-chain epochs). */
  readonly extraLeases?: readonly { readonly epoch: number; readonly dek: Uint8Array }[];
}

/** The presented token's claims (same path as the server) plus overrides (to fake the repurposed shape). */
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

/** A real wrapLeaseDek to the ephemeral key (the CRYPTO_SPEC §9.1 info construction). */
async function leaseWrapFor(input: {
  readonly ephemeralPubHex: string;
  readonly claimsDigestHex: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
}): Promise<unknown> {
  const publicKey = await importEncryptionPublicKey(hexBytes(input.ephemeralPubHex));
  if (!publicKey.ok) {
    throw new Error("ephemeral public key rejected");
  }
  const wrapped = await wrapLeaseDek({
    workloadPublicKey: publicKey.value,
    dek: input.dek,
    context: {
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
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

/** A response lease-wrapped with real crypto to the request's ephemeral key (AUTH_SPEC §14-2). */
async function leaseResponseFor(
  body: { readonly oidcToken: string; readonly ephemeralPubHex: string },
  overrides?: LeaseResponseOverrides,
): Promise<unknown> {
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
    headHashHex: built.hashes[built.hashes.length - 1],
    statement: envStatement,
    variables: resolved.variables,
    deletedVariables: [],
    ...(resolved.declaredVariables.length === 0
      ? {}
      : { declaredVariables: resolved.declaredVariables }),
    manifest: await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: resolved.currentEpoch,
      issuer: fixture.owner,
      // The declared head sits where the declared epoch is current (create = 2, rotate = 3)
      head: headOf(built, resolved.currentEpoch === 1 ? 2 : 3),
      envStatement,
      statements: [
        ...resolved.variables.map((entry) => entry.statement),
        ...resolved.declaredVariables,
      ],
    }),
    leases: [
      await wrapFor(1, dek1),
      await wrapFor(2, dek2),
      ...(await Promise.all(resolved.extraLeases.map((extra) => wrapFor(extra.epoch, extra.dek)))),
    ],
  };
}

function leasePath(projectId?: string): string {
  return `/projects/${projectId ?? fixture.built.projectId}/environments/${ENV_ID}/lease`;
}

function leaseBody(request: MockRequest): { oidcToken: string; ephemeralPubHex: string } {
  return request.body as { oidcToken: string; ephemeralPubHex: string };
}

/** Lease handler for a normal response. */
function leaseHandler(overrides?: LeaseResponseOverrides, projectId?: string): MockHandler {
  return async (request) => {
    if (request.method !== "POST" || request.path !== leasePath(projectId)) {
      return null;
    }
    return { status: 200, json: await leaseResponseFor(leaseBody(request), overrides) };
  };
}

/* -------------------------------------------------------------------------- */
/* Test environment                                                            */
/* -------------------------------------------------------------------------- */

interface CiEnv {
  readonly env: TestEnv;
  readonly server: MockServer;
  readonly oidc: OidcIssuance;
}

/**
 * CI-run environment: **seeds neither login nor config** (CI mode's keychain /
 * config independence is pinned by this setup itself — any dependency fails the command).
 */
async function startCiEnv(handlers: readonly MockHandler[]): Promise<CiEnv> {
  const oidc: OidcIssuance = { audiences: [], issued: 0 };
  const server = await MockServer.start([oidcHandler(oidc), ...handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  // Runner-supplied issuance endpoint (already has a query — also exercises the &-joining branch)
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

/** Shared check that no plaintext or token leaks into the output. */
function expectNoSecretLeak(env: TestEnv): void {
  const output = [...env.logs, ...env.errors].join("\n");
  expect(output).not.toContain("alpha-value");
  expect(output).not.toContain("beta-value");
  expect(output).not.toContain(RUNNER_TOKEN);
  // The fakeJwt payload segment (the token body) must not be printed either
  expect(output).not.toContain(base64UrlJson({ alg: "RS256", kid: "k1" }));
}

/* -------------------------------------------------------------------------- */
/* Happy path                                                                 */
/* -------------------------------------------------------------------------- */

describe("maruhi ci run (happy path)", () => {
  it("verifies and decrypts with a single lease call, injecting into the child process env", async () => {
    const { env, server, oidc } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(0);

    // Injection (memory only — ProcessRunner's extraEnv)
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "ALPHA"]);
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe("alpha-value");
    expect(env.runnerCalls[0]?.extraEnv["BETA"]).toBe("beta-value");

    // The response is self-contained (§14-2): only two calls were made — OIDC
    // issuance and lease (no chain API, no pull API)
    expect(server.requests.map((request) => request.path)).toEqual(["/oidc/token", leasePath()]);
    // audience defaults to the server origin (the AUTH_SPEC §14-1 recommended value)
    expect(oidc.audiences).toEqual([server.origin]);
    // The ephemeral key is sent as 32-byte hex
    const sent = leaseBody(server.requests[1] as MockRequest);
    expect(sent.ephemeralPubHex).toMatch(/^[0-9a-f]{64}$/);

    // Keychain/config independent (it succeeds in an environment where nothing is seeded)
    expect(env.keychain.size).toBe(0);
    // Verification success goes to stderr (stdout is kept clear for the child process)
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).toContain("Lease verified");
    expectNoSecretLeak(env);
  });

  it("--audience overrides the audience of the issuance request", async () => {
    const { env, server, oidc } = await startCiEnv([leaseHandler()]);
    const code = await runCli(ciArgs(server, ["--audience", "https://maruhi.example"]), env.layer);
    expect(code).toBe(0);
    expect(oidc.audiences).toEqual(["https://maruhi.example"]);
  });

  it("does not spawn the child process when a required = true declared is in the lease response (presence fail-fast — §1-4)", async () => {
    const declared = await statementFor({
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
    // The error text must not contain the description
    expect(errors).not.toContain("internal note");
    expectNoSecretLeak(env);
  });

  it("runs with only an informational display when a required = false declared is present", async () => {
    const declared = await statementFor({
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

/* -------------------------------------------------------------------------- */
/* §9.1 verification duties (negative cases)                                   */
/* -------------------------------------------------------------------------- */

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
    // A swapped shape: a CI config pinning a different project ID is served the
    // original project's chain. The response's declared projectId is faked to match the request (declaration consistency passes)
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
    // The shape where a wrap the server made for another sub (a job in another
    // repository) is repurposed. The HPKE info claims_digest mismatches and decryption fails (design principle 3)
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
    // pull can resolve a future head via bounded re-sync (§6.3-2b — the local
    // chain may just be stale), but a lease bundles the chain **in the same
    // response** (§14-2) so that explanation cannot exist — reject immediately
    // as a self-contradicting response. This is the only behavioral difference separating verifyLeaseDistribution from pull
    const { built, owner, dek2 } = fixture;
    const futureValue = await encryptValueFor({
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
    // No extra fetch equivalent to a re-sync (exactly one OIDC issuance and one lease call)
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
});

/* -------------------------------------------------------------------------- */
/* token-replayed / 429 / 503(AUTH_SPEC §14-3)                                */
/* -------------------------------------------------------------------------- */

/** Lease handler that returns the given error for the first `failures` calls, then responds normally. */
function flakyLeaseHandler(
  failures: number,
  error: { readonly status: number; readonly json: unknown },
): MockHandler {
  let calls = 0;
  return async (request) => {
    if (request.method !== "POST" || request.path !== leasePath()) {
      return null;
    }
    calls += 1;
    if (calls <= failures) {
      return { status: error.status, json: error.json };
    }
    return { status: 200, json: await leaseResponseFor(leaseBody(request)) };
  };
}

const TOKEN_REPLAYED = {
  status: 401,
  json: { _tag: "LeaseUnauthorized", reason: "token-replayed" },
};

describe("maruhi ci run (token-replayed / rate limit / 503)", () => {
  it("auto-retries token-replayed exactly once with a fresh token, presenting the same ephemeral key", async () => {
    const { env, server, oidc } = await startCiEnv([flakyLeaseHandler(1, TOKEN_REPLAYED)]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("Minting a fresh token and retrying once");

    const leases = server.requests.filter((request) => request.path === leasePath());
    expect(leases).toHaveLength(2);
    const [first, second] = [
      leaseBody(leases[0] as MockRequest),
      leaseBody(leases[1] as MockRequest),
    ];
    // A fresh token (different jti) + the same ephemeral key (§14-1 binding is
    // per token — the key is not rotated)
    expect(first.oidcToken).not.toBe(second.oidcToken);
    expect(first.ephemeralPubHex).toBe(second.ephemeralPubHex);
    expect(oidc.issued).toBe(2);
    expect(env.runnerCalls).toHaveLength(1);
  });

  it("stops after one retry if token-replayed persists with a fresh token (never sends a third)", async () => {
    const { env, server, oidc } = await startCiEnv([flakyLeaseHandler(99, TOKEN_REPLAYED)]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("token-replayed again with a freshly minted token");
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
    expect(env.errors.join("\n")).toContain("unsupported-issuer");
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(1);
  });

  it("does not retry on 429; reports the remaining seconds and how to re-run", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 429,
        json: { _tag: "LeaseRateLimited", retryAfterSeconds: 1800 },
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

  it("guides the fix target (coordinates / grant / policy) for 404, the uniform lease-specific response", async () => {
    // §14-1 existence hiding: unknown project, no grant, policy mismatch, and
    // out-of-scope all return the same 404. Rather than the member-facing
    // "Project not found — check the ID and your access", the guidance also lists the policy mismatch most common in CI
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 404,
        json: { _tag: "ProjectNotFound", projectId: fixture.built.projectId },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("lease-policy mismatch");
    expect(output).toContain("maruhi server grant --lease-policy");
    // No retry (neither a credential problem nor transient)
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(1);
    expect(env.runnerCalls).toHaveLength(0);
  });
});

/* -------------------------------------------------------------------------- */
/* OIDC issuance (GitHub Actions environment)                                  */
/* -------------------------------------------------------------------------- */

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
      // The abnormal shape where the issuance endpoint returns a multi-audience
      // token (placed on a separate path that does not collide with the default oidcHandler, routed via env)
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
    // The lease endpoint is never reached
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(0);
  });

  it("does not send the bearer token to a non-loopback http: issuance URL", async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    // An unroutable TEST-NET-1 address: even lenient verification would not
    // produce a real send, but correct verification means **no communication happens at all** — pinned by the response time and wording
    env.setEnvVar(OIDC_REQUEST_URL_ENV, "http://192.0.2.1/oidc/token");
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("ACTIONS_ID_TOKEN_REQUEST_URL is not a valid https:");
    expect(server.requests).toHaveLength(0);
  });

  it('does not treat a DNS name merely starting with "127." as loopback', async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    // "127.evil.com" is not a 127.0.0.0/8 literal — a public DNS name that can
    // resolve to any IP; pins the shape where prefix matching would let plaintext http through
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
    // No re-send to the redirect target (the legitimate issuance path)
    expect(
      server.requests.filter((request) => request.path.startsWith("/oidc/token")),
    ).toHaveLength(0);
  });
});

/* -------------------------------------------------------------------------- */
/* Repository anchor (§6.3 (b) — verification duty (2))                        */
/* -------------------------------------------------------------------------- */

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
    headHashHex: fixture.built.hashes[fixture.built.hashes.length - 1],
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

/* -------------------------------------------------------------------------- */
/* Argument layer (ADR-0016)                                                   */
/* -------------------------------------------------------------------------- */

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

  it("checks the --project format (genesis hash) before the network", async () => {
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
    expect(env.errors.join("\n")).toContain("genesis hash");
    expect(server.requests).toHaveLength(0);
  });

  it("a run without `--` / with no command to run is a usage error (exit 2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["ci", "run"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run");
  });
});

/* -------------------------------------------------------------------------- */
/* maruhi project anchor (generating side)                                     */
/* -------------------------------------------------------------------------- */

describe("maruhi project anchor", () => {
  it("prints anchor JSON to stdout from the verified view (in a form that passes ci run --anchor)", async () => {
    const { built, owner } = fixture;
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
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
      environments: { [ENV_ID]: 2 },
    });

    // The emitted anchor passes ci run --anchor verification as-is (round-trip consistency)
    const path = await anchorFile(anchor);
    const ci = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(ci.server, ["--anchor", path]), ci.env.layer)).toBe(0);
  });
});
