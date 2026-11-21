import { encodeHex } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

import { OIDC_CLOCK_SKEW_MS } from "../src/oidc.package/index.ts";
import { LEASE_BINDING_RETENTION_MARGIN_MS } from "../src/policy.ts";
import { JSON_HEADERS } from "./support/auth.ts";
import { createEnvironmentOk, projectId } from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario } from "./support/data-scenario.ts";
import type { LeaseBody } from "./support/lease-scenario.ts";
import {
  backfillServerWrap,
  claimsDigestOf,
  grantServer,
  malleateSignatureSegment,
  openLease,
  readyProject,
  requestLease,
  requireFirst,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { makeOidcToken } from "./support/lease.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("workload leases: the first-come binding (§14-1)", () => {
  it("rejects the same token presented with a different ephemeral key (401 token-replayed)", async () => {
    await readyProject();
    const legit = await workloadKeyPair();
    const oidcToken = await makeOidcToken();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    const thief = await workloadKeyPair();
    const replay = await requestLease({ oidcToken, ephemeralPubHex: thief.publicKeyHex });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });

    const denied = await queryProjectDo(
      projectId,
      "SELECT payload FROM audit_events WHERE event = 'server.lease_denied'",
    );
    expect(denied.length).toBe(1);
    const payload = JSON.parse(String(denied[0]?.["payload"])) as Record<string, unknown>;
    expect(payload["reason"]).toBe("token-replayed");
    expect(payload["claimsDigest"]).toBe(await claimsDigestOf());

    const windows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'issued'",
    );
    expect(windows[0]?.["count"]).toBe(1);
  });

  it("allows an idempotent retry: the same token + same ephemeral key succeeds again", async () => {
    const { dek } = await readyProject();
    const workload = await workloadKeyPair();
    const oidcToken = await makeOidcToken();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await requestLease({ oidcToken, ephemeralPubHex: workload.publicKeyHex });
      expect(response.status).toBe(200);
      const body = (await response.json()) as LeaseBody;
      const opened = await openLease({
        lease: requireFirst(body.leases, "lease"),
        workloadKeyPair: workload.pair,
        claimsDigestHex: await claimsDigestOf(),
      });
      expect(opened.ok && encodeHex(opened.value)).toBe(encodeHex(dek));
    }
    const bindings = await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM lease_bindings");
    expect(bindings[0]?.["n"]).toBe(1);
  });

  it("rejects a replayed token uniformly, regardless of the target environment's existence", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const uncreated = "env-in-scope-uncreated";
    await grantServer({ scope: [ENV, uncreated] });
    await backfillServerWrap(1, dek);
    const legit = await workloadKeyPair();
    const oidcToken = await makeOidcToken();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    const thief = await workloadKeyPair();
    for (const environmentId of [ENV, uncreated]) {
      const replay = await requestLease({
        oidcToken,
        ephemeralPubHex: thief.publicKeyHex,
        environmentId,
      });
      expect(replay.status).toBe(401);
      expect(await replay.json()).toMatchObject({ reason: "token-replayed" });
    }
  });

  it("locks a token to one ephemeral key across environments (project-wide binding — a client obligation)", async () => {
    const SECOND = "env-second-0002";
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = await createEnvironmentOk(fixture, SECOND, "App2");
    await grantServer({ scope: [ENV, SECOND] });
    await backfillServerWrap(1, dek1, ENV);
    await backfillServerWrap(1, dek2, SECOND);

    const oidcToken = await makeOidcToken();
    const workload = await workloadKeyPair();
    for (const environmentId of [ENV, SECOND]) {
      const response = await requestLease({
        oidcToken,
        ephemeralPubHex: workload.publicKeyHex,
        environmentId,
      });
      expect(response.status).toBe(200);
    }
    const rotated = await workloadKeyPair();
    const replay = await requestLease({
      oidcToken,
      ephemeralPubHex: rotated.publicKeyHex,
      environmentId: SECOND,
    });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });
  });

  it("keeps the binding alive as long as time validation can accept the token (avoiding the same-shaped hole from the PyPI audit)", async () => {
    await readyProject();
    const expSeconds = Math.floor(Date.now() / 1000) - 30;
    const oidcToken = await makeOidcToken({ expSeconds });
    const legit = await workloadKeyPair();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    const rows = await queryProjectDo(projectId, "SELECT expires_at FROM lease_bindings");
    expect(rows[0]?.["expires_at"]).toBe(expSeconds * 1000 + LEASE_BINDING_RETENTION_MARGIN_MS);
    expect(LEASE_BINDING_RETENTION_MARGIN_MS).toBeGreaterThanOrEqual(OIDC_CLOCK_SKEW_MS);

    const thief = await workloadKeyPair();
    const replay = await requestLease({ oidcToken, ephemeralPubHex: thief.publicKeyHex });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });
  });

  it("garbage-collects expired bindings when a lease is issued", async () => {
    await readyProject();
    await queryProjectDo(
      projectId,
      "INSERT INTO lease_bindings (binding_key_hex, ephemeral_pub_hex, expires_at) VALUES ('aa', 'bb', ?)",
      Date.now() - 1000,
    );
    const workload = await workloadKeyPair();
    expect(
      (
        await requestLease({
          oidcToken: await makeOidcToken(),
          ephemeralPubHex: workload.publicKeyHex,
        })
      ).status,
    ).toBe(200);
    const rows = await queryProjectDo(projectId, "SELECT binding_key_hex FROM lease_bindings");
    expect(rows.length).toBe(1);
    expect(rows[0]?.["binding_key_hex"]).not.toBe("aa");
  });

  it("binds on the signed material, not the raw token: a malleated signature segment cannot dodge the binding", async () => {
    await readyProject();
    const oidcToken = await makeOidcToken();
    const legit = await workloadKeyPair();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    const malleated = malleateSignatureSegment(oidcToken);
    expect(malleated).not.toBe(oidcToken);

    const thief = await workloadKeyPair();
    const replay = await requestLease({
      oidcToken: malleated,
      ephemeralPubHex: thief.publicKeyHex,
    });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });
  });
});

function rateLimitedLeaseAttempt(): Promise<Response> {
  return SELF.fetch(`https://maruhi.test/projects/${"ab".repeat(32)}/environments/${ENV}/lease`, {
    method: "POST",
    headers: { ...JSON_HEADERS, "cf-connecting-ip": "198.51.100.9" },
    body: JSON.stringify({ oidcToken: "aaaa.bbbb.cccc", ephemeralPubHex: "cd".repeat(32) }),
  });
}

describe("workload leases: the source-IP request-level rate limit", () => {
  it("a barrage from a fixed IP gets a 429 before reaching OIDC verification or DO creation", async () => {
    const responses: Response[] = [];
    for (let batch = 0; batch < 4; batch += 1) {
      responses.push(
        ...(await Promise.all(Array.from({ length: 31 }, () => rateLimitedLeaseAttempt()))),
      );
    }
    let limited: Response | null = null;
    for (const response of responses) {
      if (response.status === 429 && limited === null) {
        limited = response;
      } else if (response.status !== 429) {
        expect(response.status).toBe(401);
      }
    }
    expect(limited).not.toBeNull();
    expect(limited?.headers.get("retry-after")).toMatch(/^\d+$/);
    const body = (await limited?.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("LeaseRateLimited");
    expect(body["scope"]).toBe("source-address");
    expect(body["retryAfterSeconds"] as number).toBeGreaterThan(0);
  }, 120_000);
});
