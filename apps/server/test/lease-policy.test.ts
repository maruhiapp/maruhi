// Integration tests for workload-lease 503s and auditing (AUTH_SPEC
// §14-3 / AUDIT_SPEC §3.5), deployments with an unset server key, and
// the acceptance policy.
// For how the suite is split see the top of lease.test.ts; shared
// helpers are in support/lease-scenario.ts.
//
// What this suite pins:
// - auditing (AUDIT_SPEC §3.5): the granularity of
//   server.dek_unwrapped / server.lease_issued / server.lease_denied,
//   and that NO var.read is recorded

import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { AuditStore } from "../src/audit-store.ts";
import { ChainStore } from "../src/chain-store.ts";
import { DataStore } from "../src/data-store.ts";
import { MAX_LEASES_PER_WINDOW } from "../src/policy.ts";
import { leaseProgram } from "../src/programs-lease.ts";
import { makeServerKey, ServerKey } from "../src/server-key.ts";
import { StorageMeter } from "../src/storage-guard.ts";
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
import {
  backfillServerWrap,
  grantServer,
  readyProject,
  requestLease,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** One variable + advance to epoch 2, with the grant and every epoch's backfill done. */
async function twoEpochProject(): Promise<{ readonly fpHex: string }> {
  const dek1 = await createEnvironmentOk(fixture, ENV, "App");
  await createVariableOk(dek1, VAR, "DATABASE_URL", "postgres://alpha");
  const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
  const fpHex = await grantServer({ scope: [ENV] });
  await backfillServerWrap(1, dek1);
  await backfillServerWrap(2, dek2);
  return { fpHex };
}

describe("workload leases: 503s and auditing (§14-3 / AUDIT_SPEC §3.5)", () => {
  it("returns 503 server-wraps-missing when the grant is valid but the re-wrap is pending", async () => {
    // Grant exists but never backfilled = the CRYPTO_SPEC §7 re-wrap
    // is unfinished. Do not make this an opaque failure (the A1
    // ruling: the lease is the last line of defense)
    await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({ scope: [ENV] });
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ reason: "server-wraps-missing" });
  });

  it("returns 503 when the grant backfill covered only some of the existing epochs", async () => {
    // A rotation composite on an environment with a valid grant
    // requires the complete wrap set including the server key (§12-4),
    // so a gap cannot be produced via rotate. The realistic source is
    // "granted an environment that already had epochs, then the
    // backfill partially missed" (A1 ruling 4: the only reconciliation
    // means is the 409 — the lease is the last line of defense)
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    await grantServer({ scope: [ENV] });
    // Backfill only epoch 1, dropping the current epoch 2
    await backfillServerWrap(1, dek1);
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ reason: "server-wraps-missing" });
  });

  it("records dek_unwrapped per epoch, actor = the server key", async () => {
    const { fpHex } = await twoEpochProject();
    const workload = await workloadKeyPair();
    expect(
      (
        await requestLease({
          oidcToken: await makeOidcToken(),
          ephemeralPubHex: workload.publicKeyHex,
        })
      ).status,
    ).toBe(200);

    const unwrapped = await queryProjectDo(
      projectId,
      "SELECT epoch, actor_type, actor_key_fingerprint, environment_id FROM audit_events WHERE event = 'server.dek_unwrapped' ORDER BY epoch",
    );
    expect(unwrapped.map((row) => row["epoch"])).toEqual([1, 2]);
    expect(unwrapped[0]?.["actor_type"]).toBe("server");
    expect(unwrapped[0]?.["actor_key_fingerprint"]).toBe(fpHex);
    expect(unwrapped[0]?.["environment_id"]).toBe(ENV);
  });

  it("records lease_issued once per environment with the derived grant_chain_seq", async () => {
    const { fpHex } = await twoEpochProject();
    const workload = await workloadKeyPair();
    await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });

    const issued = await queryProjectDo(
      projectId,
      "SELECT variable_id, actor_key_fingerprint, payload FROM audit_events WHERE event = 'server.lease_issued'",
    );
    // One row per environment (no per-variable granularity option — §3.5)
    expect(issued.length).toBe(1);
    expect(issued[0]?.["variable_id"]).toBeNull();
    expect(issued[0]?.["actor_key_fingerprint"]).toBe(fpHex);
    const payload = JSON.parse(String(issued[0]?.["payload"])) as Record<string, unknown>;
    // grant_chain_seq is the chain-derived grant_seq (not
    // re-implemented on the server side). **Pin by value**: watching
    // only the type would let a wrong seq (e.g. a stale pre-re-grant
    // seq) slide through
    const granted = await queryProjectDo(
      projectId,
      "SELECT chain_seq FROM audit_events WHERE event = 'chain.server_granted'",
    );
    expect(granted.length).toBe(1);
    expect(payload["grantChainSeq"]).toBe(granted[0]?.["chain_seq"]);
    expect(typeof payload["claimsDigest"]).toBe("string");
    expect(payload["epochs"]).toEqual([1, 2]);
  });

  it("records no var.read for a lease (§14-4)", async () => {
    await twoEpochProject();
    const before = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    const workload = await workloadKeyPair();
    await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    // var.read is the evidence of a human actor's read; disclosure to
    // a workload is carried by the server.* events (AUDIT_SPEC §3.3 /
    // §14-4)
    const after = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    expect(after[0]?.["n"]).toBe(before[0]?.["n"]);
  });
});

describe("workload leases: deployment with an unset server key (§14-3)", () => {
  // The DO derives its keypair from its own env (chain-do.ts), so
  // handing the worker a different env changes nothing on the DO side.
  // What is checked here at the program level is "with no key, fail
  // BEFORE reading the chain" — if the order breaks, a "unknown = 404
  // / exists = 503" gap appears, and the unauthenticated lease surface
  // becomes usable for project-existence probing (§11-2)
  it("fails before touching the chain store (the order decides existence hiding)", async () => {
    let chainLoads = 0;
    const chainStore = ChainStore.of({
      load: Effect.sync(() => {
        chainLoads += 1;
        throw new Error("chain must not be read when the server key is unconfigured");
      }),
      insertSync: () => {
        throw new Error("unreachable");
      },
    });
    const outcome = await Effect.runPromise(
      leaseProgram(
        ENV,
        "00".repeat(32),
        {
          issuer: OIDC_ISSUER,
          subject: LEASE_SUBJECT,
          audiences: [LEASE_AUDIENCE],
          claims: {},
          claimsDigestHex: "00".repeat(32),
          bindingKeyHex: "11".repeat(32),
          bindingExpiresAtMs: Date.now() + 300_000,
        },
        { current: null, chain: null },
      ).pipe(
        Effect.match({
          onSuccess: () => ({ ok: true as const }),
          onFailure: (rejection) => ({ ok: false as const, rejection }),
        }),
        // makeServerKey(undefined) = an unset-key deployment.
        // DataStore / AuditStore are unreachable, so this path also
        // pins that they are never referenced
        Effect.provideService(ServerKey, makeServerKey(undefined)),
        Effect.provideService(ChainStore, chainStore),
        Effect.provideService(DataStore, undefined as never),
        Effect.provideService(AuditStore, undefined as never),
        // The storage guard's observation point (§12-8) is just before issuance = unreachable on this path
        Effect.provideService(StorageMeter, undefined as never),
      ),
    );
    expect(outcome).toEqual({
      ok: false,
      rejection: { kind: "unavailable", reason: "server-key-unconfigured" },
    });
    expect(chainLoads).toBe(0);
  });
});

describe("workload leases: acceptance policy (§14-3)", () => {
  it("rejects an oversized OIDC token at the schema boundary (400)", async () => {
    const workload = await workloadKeyPair();
    const oversized = `${"a".repeat(20_000)}.${"b".repeat(16)}.${"c".repeat(16)}`;
    const response = await requestLease({
      oidcToken: oversized,
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(400);
  });

  it("rejects a malformed ephemeral public key at the schema boundary (400)", async () => {
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: "not-hex",
    });
    expect(response.status).toBe(400);
  });

  it("returns 429 with retryAfterSeconds once the project window is exhausted", async () => {
    const { dek } = await readyProject();
    expect(dek.length).toBe(32);
    const workload = await workloadKeyPair();
    // Fill the window directly (300 real requests do not justify the
    // runtime). The counter is the lease_windows row in DO SQLite; go
    // through the same read-modify-write as the implementation
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_windows (kind, window_start, count) VALUES ('issued', ?, ?) ON CONFLICT(kind) DO UPDATE SET window_start = excluded.window_start, count = excluded.count",
      Date.now(),
      MAX_LEASES_PER_WINDOW,
    );
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(429);
    const body = (await response.json()) as { retryAfterSeconds: number };
    // Since the window was seeded just now with window_start = now,
    // the remainder is fixed to near the window length (1 hour).
    // Checking only > 0 would not catch an order-of-magnitude
    // regression
    expect(body.retryAfterSeconds).toBeGreaterThan(3500);
    expect(body.retryAfterSeconds).toBeLessThanOrEqual(3600);
  });

  it("does not consume the window when the lease cannot be issued (503 stays diagnosable)", async () => {
    // If the 503 path consumed the window, a backfill-missed project's
    // CI would eat slots on every retry, and past the 300th the
    // "fixable diagnosis" 503 would mutate into an unrelated 429.
    // Consumption happens only when a lease is actually issued
    await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({ scope: [ENV] }); // never backfilled = server-wraps-missing
    const workload = await workloadKeyPair();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await requestLease({
        oidcToken: await makeOidcToken(),
        ephemeralPubHex: workload.publicKeyHex,
      });
      expect(response.status).toBe(503);
    }
    const rows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'issued'",
    );
    expect(rows.length).toBe(0);
  });

  it("consumes exactly one window slot per issued lease", async () => {
    await readyProject();
    const workload = await workloadKeyPair();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await requestLease({
        oidcToken: await makeOidcToken(),
        ephemeralPubHex: workload.publicKeyHex,
      });
      expect(response.status).toBe(200);
    }
    const rows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'issued'",
    );
    expect(rows[0]?.["count"]).toBe(2);
  });

  it("does not let an unauthorized caller consume the project's lease window", async () => {
    // A policy mismatch (404) does not consume the issuance window —
    // if it did, a third party could starve a legitimate workload's
    // leases
    await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({ scope: [ENV], leasePolicy: [] });
    const workload = await workloadKeyPair();
    await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'issued'",
    );
    expect(rows.length).toBe(0);
  });
});
