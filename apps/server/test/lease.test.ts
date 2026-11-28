import { LeaseResponseSchema } from "@maruhi/api-schema";
import { computeChainEntryHash, decryptVariable, encodeHex } from "@maruhi/crypto";
import { hexBytes, testEnvironmentId, testProjectId, testVariableId } from "@maruhi/test-kit";
import { env, runInDurableObject } from "cloudflare:test";
import { Cause, Effect, Exit, Schema } from "effect";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { chainStoreLayer, type StateCache } from "../src/do/chain-store.ts";
import { leaseChainProgram } from "../src/programs/programs-lease.ts";
import {
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  rotateEnvironmentOk,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  declareVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  VAR,
} from "./support/data-scenario.ts";
import type { LeaseBody } from "./support/lease-scenario.ts";
import {
  backfillServerWrap,
  claimsDigestOf,
  grantServer,
  openLease,
  readyProject,
  requestLease,
  requireFirst,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { callProjectDo, queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("workload leases: issuance (AUTH_SPEC §14-2 / CRYPTO_SPEC §9.1)", () => {
  it("issues a lease the workload can open with the same epoch DEK (the server never decrypts a value)", async () => {
    const { dek } = await readyProject();
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("content-length")).toBeNull();
    const body = (await response.json()) as LeaseBody;
    expect(() => Schema.decodeUnknownSync(LeaseResponseSchema)(body)).not.toThrow();

    const stored = await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries");
    expect(body.chain.length).toBe(stored[0]?.["n"]);
    expect(body.headSeq).toBe(body.chain.length);
    expect(body.currentEpoch).toBe(1);

    expect(body.manifest).toMatchObject({ manifestVersion: 2, epoch: 1 });

    expect(body.leases.length).toBe(1);
    const lease = requireFirst(body.leases, "lease");
    expect(Object.keys(lease).toSorted()).toEqual(["ciphertextHex", "encHex", "epoch", "suite"]);

    const opened = await openLease({
      lease,
      workloadKeyPair: workload.pair,
      claimsDigestHex: await claimsDigestOf(),
    });
    expect(opened.ok).toBe(true);
    expect(opened.ok && encodeHex(opened.value)).toBe(encodeHex(dek));
  });

  it("answers with a server fault when the stored manifest row is missing (0.28-draft)", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    await queryProjectDo(
      projectId,
      "DELETE FROM environment_manifests WHERE environment_id = ?",
      ENV,
    );
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(500);
    const body = await response.text();
    expect(body).not.toContain(ENV);
    expect(body).not.toContain("manifestVersion");
    await expect(
      callProjectDo(projectId, async (instance) =>
        instance.issueLease(testEnvironmentId(ENV), workload.publicKeyHex, {
          issuer: OIDC_ISSUER,
          subject: LEASE_SUBJECT,
          audiences: [LEASE_AUDIENCE],
          claims: { iss: OIDC_ISSUER, sub: LEASE_SUBJECT, aud: LEASE_AUDIENCE },
          claimsDigestHex: await claimsDigestOf(),
          bindingKeyHex: "b1".repeat(32),
          bindingExpiresAtMs: Date.now() + 600_000,
        }),
      ),
    ).rejects.toThrow("environment manifest row missing");
  });

  it("answers a server fault, not a partial stream, when the response fails its schema (§14-2)", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    await queryProjectDo(projectId, "UPDATE variable_versions SET nonce_hex = 'not-hex'");
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(500);
    const body = await response.text();
    expect(body).not.toContain("not-hex");
    expect(body).not.toContain(projectId);
  });

  it("bundles the stored checkpoint-time value snapshot (§14-2)", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as LeaseBody & {
      readonly checkpointSnapshot?: {
        readonly chainSeq: number;
        readonly entryHashHex: string;
        readonly values: readonly unknown[];
      };
    };
    const stored = await queryProjectDo(
      projectId,
      "SELECT chain_seq, entry_hash_hex FROM environment_checkpoints WHERE environment_id = ?",
      ENV,
    );
    expect(body.checkpointSnapshot).toBeDefined();
    expect(body.checkpointSnapshot?.chainSeq).toBe(stored[0]?.["chain_seq"]);
    expect(body.checkpointSnapshot?.entryHashHex).toBe(stored[0]?.["entry_hash_hex"]);
    expect(body.checkpointSnapshot?.values).toEqual([]);
  });

  it("returns values as ciphertext the workload decrypts with the leased DEK", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    const body = (await response.json()) as LeaseBody;
    const opened = await openLease({
      lease: requireFirst(body.leases, "lease"),
      workloadKeyPair: workload.pair,
      claimsDigestHex: await claimsDigestOf(),
    });
    if (!opened.ok) {
      throw new Error("lease unwrap failed");
    }
    const variable = requireFirst(body.variables, "variable");
    expect(variable.variableId).toBe(VAR);
    const plaintext = await decryptVariable({
      dek: opened.value,
      nonce: hexBytes(variable.value.nonceHex),
      ciphertext: hexBytes(variable.value.ciphertextHex),
      context: {
        projectId: testProjectId(projectId),
        environmentId: testEnvironmentId(ENV),
        epoch: 1,
        variableId: testVariableId(VAR),
        version: 1,
      },
    });
    expect(plaintext.ok && new TextDecoder().decode(plaintext.value)).toBe("postgres://alpha");
  });

  it("binds the lease to the workload context: another job's claims_digest cannot open it", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    const body = (await response.json()) as LeaseBody;
    const opened = await openLease({
      lease: requireFirst(body.leases, "lease"),
      workloadKeyPair: workload.pair,
      claimsDigestHex: await claimsDigestOf("repo:maruhi-test/demo:ref:refs/heads/feature-x"),
    });
    expect(opened.ok).toBe(false);
  });

  it("leases every epoch the response's latest values use, plus the current epoch (§14-2)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek1, VAR, "DATABASE_URL", "postgres://alpha");
    const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    await grantServer({ scope: [ENV] });
    await backfillServerWrap(1, dek1);
    await backfillServerWrap(2, dek2);

    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as LeaseBody;
    expect(body.leases.map((lease) => lease.epoch).toSorted()).toEqual([1, 2]);
  });

  it("bundles the statements of declared variables (§14-2 — §12-7's distribution rules)", async () => {
    await readyProject();
    await declareVariableOk({ variableId: "var-declared-0001", name: "DECLARED" });
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as LeaseBody & {
      readonly declaredVariables?: readonly { readonly variableId: string }[];
    };
    expect(body.declaredVariables?.map((statement) => statement.variableId)).toEqual([
      "var-declared-0001",
    ]);
  });

  it("reads the chain in a second RPC, cut at the head the issuance was judged against (§14-2 — Sc-3a)", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    const issue = async (bindingKeyHex: string) => {
      const outcome = await callProjectDo(projectId, async (instance) =>
        instance.issueLease(testEnvironmentId(ENV), workload.publicKeyHex, {
          issuer: OIDC_ISSUER,
          subject: LEASE_SUBJECT,
          audiences: [LEASE_AUDIENCE],
          claims: { iss: OIDC_ISSUER, sub: LEASE_SUBJECT, aud: LEASE_AUDIENCE },
          claimsDigestHex: await claimsDigestOf(),
          bindingKeyHex,
          bindingExpiresAtMs: Date.now() + 600_000,
        }),
      );
      if (outcome.kind !== "ok") {
        throw new Error("lease not issued");
      }
      expect("chain" in outcome.value).toBe(false);
      return {
        token: outcome.chainToken,
        head: { seq: outcome.value.headSeq, hashHex: outcome.value.headHashHex },
      };
    };
    const readChain = (token: string) =>
      callProjectDo(projectId, (instance) => instance.leaseChain(token));
    const tupleLess = {
      op: "checkpoint" as const,
      payload: { environments: [], auditHeadHashHex: "" },
    };
    const a = await issue("b2".repeat(32));
    expect(a.head).toEqual(fixture.head);
    await appendOperation(fixture, OWNER, tupleLess);
    const b = await issue("b3".repeat(32));
    expect(b.head.seq).toBe(a.head.seq + 1);
    await appendOperation(fixture, OWNER, tupleLess);
    await expect(readChain("00".repeat(32))).rejects.toThrow(
      "unknown, spent or expired lease chain token",
    );
    for (const lease of [a, b]) {
      const chain = await readChain(lease.token);
      expect(chain.length).toBe(lease.head.seq);
      expect(await computeChainEntryHash(requireFirst(chain.slice(-1), "entry"))).toBe(
        lease.head.hashHex,
      );
      await expect(readChain(lease.token)).rejects.toThrow(
        "unknown, spent or expired lease chain token",
      );
    }
  });

  it("refuses a lease head that is not on the stored chain as a broken invariant (§14-2)", async () => {
    await readyProject();
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    const exit = await runInDurableObject(stub, (_instance, state) => {
      const cache: StateCache = { current: null, chain: null };
      return Effect.runPromiseExit(
        leaseChainProgram({ seq: fixture.head.seq, hashHex: "00".repeat(32) }, cache).pipe(
          Effect.provide(chainStoreLayer(state.storage.sql, cache)),
        ),
      );
    });
    expect(Exit.isFailure(exit) && Cause.pretty(exit.cause)).toContain(
      "the lease head is not on the stored chain",
    );
  });
});

describe("workload leases: OIDC verification (§14-1's authentication stage — 401)", () => {
  beforeEach(async () => {
    await readyProject();
  });

  const cases: readonly {
    readonly name: string;
    readonly token: () => Promise<string>;
    readonly reason: string;
  }[] = [
    {
      name: "unsupported issuer",
      token: () => makeOidcToken({ issuer: "https://evil.example" }),
      reason: "unsupported-issuer",
    },
    {
      name: "unsupported alg (header says RS256 but the key is EC)",
      token: () => makeOidcToken({ alg: "RS256" }),
      reason: "unsupported-alg",
    },
    {
      name: "unknown kid",
      token: () => makeOidcToken({ kid: "rotated-away" }),
      reason: "unknown-key",
    },
    {
      name: "tampered signature",
      token: () => makeOidcToken({ tamperSignature: true }),
      reason: "signature-invalid",
    },
    {
      name: "expired token",
      token: () => makeOidcToken({ expSeconds: Math.floor(Date.now() / 1000) - 600 }),
      reason: "token-expired",
    },
    {
      name: "iat in the future beyond the skew",
      token: () => makeOidcToken({ iatSeconds: Math.floor(Date.now() / 1000) + 600 }),
      reason: "token-not-yet-valid",
    },
    {
      name: "missing exp",
      token: () => makeOidcToken({ omit: ["exp"] }),
      reason: "missing-claim",
    },
  ];

  for (const testCase of cases) {
    it(`rejects ${testCase.name} with 401 ${testCase.reason}`, async () => {
      const workload = await workloadKeyPair();
      const response = await requestLease({
        oidcToken: await testCase.token(),
        ephemeralPubHex: workload.publicKeyHex,
      });
      expect(response.status).toBe(401);
      expect(await response.json()).toMatchObject({ reason: testCase.reason });
    });
  }

  it("rejects a multi-audience token with ambiguous-audience, not missing-claim", async () => {
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken({ audience: [LEASE_AUDIENCE, "https://other.example"] }),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ reason: "ambiguous-audience" });
  });

  it("records no lease_denied for tokens that fail signature verification (AUDIT_SPEC §3.5)", async () => {
    const workload = await workloadKeyPair();
    await requestLease({
      oidcToken: await makeOidcToken({ tamperSignature: true }),
      ephemeralPubHex: workload.publicKeyHex,
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'server.lease_denied'",
    );
    expect(rows[0]?.["n"]).toBe(0);
  });

  it("rejects a token whose alg is outside the allowlist even with a valid signature", async () => {
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken({ alg: "none" }),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ reason: "unsupported-alg" });
  });
});
