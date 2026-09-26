// Integration tests for the workload-lease API (AUTH_SPEC §14 =
// CRYPTO_SPEC §9.1) — issuance (§14-2) and the OIDC verification stage
// (§14-1's 401s).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
//
// How the lease suites are split (shared helpers in
// support/lease-scenario.ts; for the split's motivation see the top of
// support/membership-scenario.ts):
// - lease.test.ts (this file): issuance and OIDC verification. That the
//   lease wrap binds claims_digest into info and cannot be opened under
//   a different workload context (CRYPTO_SPEC §9.1). That no plaintext
//   value or DEK appears in the response
// - lease-authz.test.ts: authorization and existence hiding (§14-1 /
//   §11-2 — a uniform 404)
// - lease-policy.test.ts: 503 and auditing (§14-3 / AUDIT_SPEC §3.5),
//   unset server key, acceptance policy
// - lease-binding.test.ts: first-come binding (§14-1) and source-IP
//   rate limits

import { decryptVariable, encodeHex } from "@maruhi/crypto";
import { beforeEach, describe, expect, it } from "vitest";

import { hexBytes } from "./support/data-crypto.ts";
import {
  createEnvironmentOk,
  MEMBER,
  projectId,
  rotateEnvironmentOk,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
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
import { LEASE_AUDIENCE, makeOidcToken } from "./support/lease.ts";
import { queryProjectDo } from "./support/project-do.ts";

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
    const body = (await response.json()) as LeaseBody;

    // The response bundles the chain (non-members get a 404 from the
    // chain API — §11-2). The length is exactly determined by the
    // fixture, so pin it by value
    const stored = await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM chain_entries");
    expect(body.chain.length).toBe(stored[0]?.["n"]);
    expect(body.headSeq).toBe(body.chain.length);
    expect(body.currentEpoch).toBe(1);

    // Bundles the latest environment manifest + issuer info (§14-2 —
    // material for the workload's verification obligation §9.1 (5))
    expect(
      (body as { manifest?: { manifestVersion: number; epoch: number; issuerUserId: string } })
        .manifest,
    ).toMatchObject({ manifestVersion: 2, epoch: 1 });

    // The lease wrap carries no registered signature or signer info
    // (server-generated and response-scoped — no signer can exist on
    // the chain — §9.1)
    expect(body.leases.length).toBe(1);
    const lease = requireFirst(body.leases, "lease");
    expect(Object.keys(lease).toSorted()).toEqual(["ciphertextHex", "encHex", "epoch", "suite"]);

    const opened = await openLease({
      lease,
      workloadKeyPair: workload.pair,
      claimsDigestHex: await claimsDigestOf(),
    });
    expect(opened.ok).toBe(true);
    // The leased DEK is the original epoch DEK itself (the server only intermediated)
    expect(opened.ok && encodeHex(opened.value)).toBe(encodeHex(dek));
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
    // The supply source is the stored row from checkpoint acceptance
    // itself (§16-2 — the environment creation's boundary checkpoint is
    // the baseline from birth. A variable created after it is not in
    // that enumeration)
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
      context: { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 1 },
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
      // A different subject under the same issuer / audience (a different branch) = a different workload context
      claimsDigestHex: await claimsDigestOf("repo:maruhi-test/demo:ref:refs/heads/feature-x"),
    });
    expect(opened.ok).toBe(false);
  });

  it("leases every epoch the response's latest values use, plus the current epoch (§14-2)", async () => {
    // Create a value at epoch 1, then rotate to epoch 2. The value remains at epoch 1, not re-encrypted
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
    // `aud` does exist (there are merely several). Kept as a separate
    // vocabulary so an operator guided by the reason code does not go
    // looking for a claim that exists
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
    // `none` satisfies Schema's compact-JWS shape (3 segments) and
    // then falls at the alg allowlist — an implementation that trusts
    // the header's alg breaks here
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken({ alg: "none" }),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ reason: "unsupported-alg" });
  });
});
