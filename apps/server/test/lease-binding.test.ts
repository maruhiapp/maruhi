// Integration tests for the workload-lease first-come binding
// (AUTH_SPEC §14-1) and the source-IP request-level rate limit.
// For how the suite is split see the top of lease.test.ts; shared
// helpers are in support/lease-scenario.ts.
//
// What this suite pins (§14-1): rejecting the same token with a
// different key, an idempotent retry with the same key, the alignment
// of the retention period with time validation's acceptance window,
// and the GC of expired bindings.

import { encodeHex } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

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

    // A copy of the stolen token + the attacker's own ephemeral key
    const thief = await workloadKeyPair();
    const replay = await requestLease({ oidcToken, ephemeralPubHex: thief.publicKeyHex });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });

    // Audit (AUDIT_SPEC §3.5): a lease_denied remains, and its
    // claims_digest equals the legitimate issuance's = the owner can
    // cross-reference "which workload's token was stolen"
    const denied = await queryProjectDo(
      projectId,
      "SELECT payload FROM audit_events WHERE event = 'server.lease_denied'",
    );
    expect(denied.length).toBe(1);
    const payload = JSON.parse(String(denied[0]?.["payload"])) as Record<string, unknown>;
    expect(payload["reason"]).toBe("token-replayed");
    expect(payload["claimsDigest"]).toBe(await claimsDigestOf());

    // The rejection does not consume the rate window (still 1 issued — §14-3)
    const windows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'issued'",
    );
    expect(windows[0]?.["count"]).toBe(1);
  });

  it("allows an idempotent retry: the same token + same ephemeral key succeeds again", async () => {
    // A legitimate retry after a lost response. Idempotency (§14-1) so
    // retries keep working even if a pre-issued issuer that cannot
    // re-issue tokens at runtime (GitLab etc.) is added later
    const { dek } = await readyProject();
    const workload = await workloadKeyPair();
    const oidcToken = await makeOidcToken();
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await requestLease({ oidcToken, ephemeralPubHex: workload.publicKeyHex });
      expect(response.status).toBe(200);
      // The retry's response is also a real, openable lease (not empty-response idempotency)
      const body = (await response.json()) as LeaseBody;
      const opened = await openLease({
        lease: requireFirst(body.leases, "lease"),
        workloadKeyPair: workload.pair,
        claimsDigestHex: await claimsDigestOf(),
      });
      expect(opened.ok && encodeHex(opened.value)).toBe(encodeHex(dek));
    }
    // The binding row stays at 1 (not overwritten)
    const bindings = await queryProjectDo(projectId, "SELECT COUNT(*) AS n FROM lease_bindings");
    expect(bindings[0]?.["n"]).toBe(1);
  });

  it("rejects a replayed token uniformly, regardless of the target environment's existence", async () => {
    // The judgment precedes environment existence (§14-3): do not tell
    // a holder of a bound token's copy whether the environment exists
    // via a 401-vs-404 difference
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
    // The binding is per-token and shared without crossing project DOs
    // (environmentId is not part of the key). Since the endpoint is
    // per-environment, a job leasing N environments with one token must
    // present **the same ephemeral key on every request**. That is a
    // client obligation (one ephemeral key per token, no per-request
    // rotation — AUTH_SPEC §14-1). Pinned while loose because it bites
    // hardest on pre-issued issuers that cannot re-issue at runtime
    // (GitLab etc.).
    const SECOND = "env-second-0002";
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = await createEnvironmentOk(fixture, SECOND, "App2");
    await grantServer({ scope: [ENV, SECOND] });
    await backfillServerWrap(1, dek1, ENV);
    await backfillServerWrap(1, dek2, SECOND);

    const oidcToken = await makeOidcToken();
    const workload = await workloadKeyPair();
    // The same token + same key can lease multiple environments
    for (const environmentId of [ENV, SECOND]) {
      const response = await requestLease({
        oidcToken,
        ephemeralPubHex: workload.publicKeyHex,
        environmentId,
      });
      expect(response.status).toBe(200);
    }
    // Rotating the key on a different environment is a 401 (the
    // binding is per-token and pins the key — it does not allow
    // "leasing under your own key" for an unbound environment = the
    // path of leasing another environment with a stolen token is
    // blocked at the same time)
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
    // A past exp still passes time validation within skew (±60 s). If
    // the binding's retention were shorter than the acceptance window,
    // the difference alone would be a replay window (why policy.ts
    // derives the retention margin from skew — the precedent in
    // docs/notes/session-24.md §2)
    await readyProject();
    const expSeconds = Math.floor(Date.now() / 1000) - 30; // past, but within skew
    const oidcToken = await makeOidcToken({ expSeconds });
    const legit = await workloadKeyPair();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    // The binding row's lifetime = exp + retention margin (margin ≥ skew is guaranteed by the derivation)
    const rows = await queryProjectDo(projectId, "SELECT expires_at FROM lease_bindings");
    expect(rows[0]?.["expires_at"]).toBe(expSeconds * 1000 + LEASE_BINDING_RETENTION_MARGIN_MS);
    expect(LEASE_BINDING_RETENTION_MARGIN_MS).toBeGreaterThanOrEqual(OIDC_CLOCK_SKEW_MS);

    // A replay within the remainder of the acceptance window hits the binding and is rejected
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
    // Expired rows are GC'd at issuance time; only this run's binding remains
    const rows = await queryProjectDo(projectId, "SELECT binding_key_hex FROM lease_bindings");
    expect(rows.length).toBe(1);
    expect(rows[0]?.["binding_key_hex"]).not.toBe("aa");
  });

  it("binds on the signed material, not the raw token: a malleated signature segment cannot dodge the binding", async () => {
    // Regression guard: if the binding key were a hash of the raw
    // token, swapping the signature-unprotected third segment's
    // base64url tail for "another character that decodes identically"
    // would change the hash while leaving signature verification and
    // claims_digest untouched — the binding lookup misses and the
    // replay goes through. Pin that hashing the signing input
    // (header.payload) as the binding key closes this path.
    await readyProject();
    const oidcToken = await makeOidcToken();
    const legit = await workloadKeyPair();
    expect((await requestLease({ oidcToken, ephemeralPubHex: legit.publicKeyHex })).status).toBe(
      200,
    );

    const malleated = malleateSignatureSegment(oidcToken);
    // Confirm the premise: the malleated token differs as a raw string (a naive hash differs)
    expect(malleated).not.toBe(oidcToken);

    const thief = await workloadKeyPair();
    const replay = await requestLease({
      oidcToken: malleated,
      ephemeralPubHex: thief.publicKeyHex,
    });
    // The mutation passes signature verification (= it is not
    // signature-invalid) but the signing input is unchanged, so it hits
    // the binding and becomes token-replayed. If this returned to 200,
    // replay evasion by a one-character edit would be back
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reason: "token-replayed" });
  });
});

// A barrage against a nonexistent project ID: the limit sits before
// projectStub, so no DO is created. The shape passes the Schema (the
// base64url + `.` character set) and falls at OIDC verification — the
// limit judgment lives in the handler (after the Schema pass), so a
// shape the Schema rejects would never be counted
function rateLimitedLeaseAttempt(): Promise<Response> {
  return SELF.fetch(`https://maruhi.test/projects/${"ab".repeat(32)}/environments/${ENV}/lease`, {
    method: "POST",
    headers: { ...JSON_HEADERS, "cf-connecting-ip": "198.51.100.9" },
    body: JSON.stringify({ oidcToken: "aaaa.bbbb.cccc", ephemeralPubHex: "cd".repeat(32) }),
  });
}

describe("workload leases: the source-IP request-level rate limit", () => {
  it("a barrage from a fixed IP gets a 429 before reaching OIDC verification or DO creation", async () => {
    // The judgment is by IP alone and unrelated to project state, so
    // exposing the 429 does not break existence hiding (§11-2)
    // The window is a wall-clock-aligned fixed window (60/60s):
    // sequentially, a slow runner cannot fit 61 requests in one window
    // and flakes. Parallel bursts fit 2 windows + 2 (124 requests) into
    // a few seconds — even if a minute boundary lands mid-burst, one
    // window always takes 62 requests and returns the 429
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
        // The un-limited ones get the normal authentication-stage rejection (401 malformed-token)
        expect(response.status).toBe(401);
      }
    }
    expect(limited).not.toBeNull();
    // It also carries an RFC 9110 Retry-After header (backoff material
    // for clients other than the maruhi CLI — index.ts's
    // withRetryAfterHeader)
    expect(limited?.headers.get("retry-after")).toMatch(/^\d+$/);
    const body = (await limited?.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("LeaseRateLimited");
    expect(body["scope"]).toBe("source-address");
    expect(body["retryAfterSeconds"] as number).toBeGreaterThan(0);
    // A 124-request burst can exceed the default 15s depending on
    // overall suite load (measured on a full-suite run). The fixture's
    // beforeEach issuing PATs through the real path (the CLI login
    // handoff = 6 round trips per user) is also included in this
    // measurement. Extended while keeping hang detection bounded
  }, 120_000);
});
