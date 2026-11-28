import { testEnvironmentId } from "@maruhi/test-kit";
import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { AuditStore } from "../src/audit-store.ts";
import { DataStore } from "../src/data.package/index.ts";
import { ChainStore } from "../src/do/chain-store.ts";
import { MAX_LEASES_PER_WINDOW } from "../src/policy.ts";
import { leaseProgram } from "../src/programs/programs-lease.ts";
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
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    await grantServer({ scope: [ENV] });
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
    expect(issued.length).toBe(1);
    expect(issued[0]?.["variable_id"]).toBeNull();
    expect(issued[0]?.["actor_key_fingerprint"]).toBe(fpHex);
    const payload = JSON.parse(String(issued[0]?.["payload"])) as Record<string, unknown>;
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
    const after = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    expect(after[0]?.["n"]).toBe(before[0]?.["n"]);
  });
});

describe("workload leases: deployment with an unset server key (§14-3)", () => {
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
        testEnvironmentId(ENV),
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
        Effect.provideService(ServerKey, makeServerKey(undefined)),
        Effect.provideService(ChainStore, chainStore),
        Effect.provideService(DataStore, undefined as never),
        Effect.provideService(AuditStore, undefined as never),
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
    expect(body.retryAfterSeconds).toBeGreaterThan(3500);
    expect(body.retryAfterSeconds).toBeLessThanOrEqual(3600);
  });

  it("does not consume the window when the lease cannot be issued (503 stays diagnosable)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({ scope: [ENV] });
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
