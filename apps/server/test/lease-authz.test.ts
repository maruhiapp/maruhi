// Integration tests for workload-lease authorization and existence
// hiding (AUTH_SPEC §14-1 / §11-2 — a uniform 404). Pin that no grant,
// a policy mismatch, out-of-scope, a missing environment, and an
// uninitialized project are ALL the same 404 (no reason leaks). Shared
// helpers are in support/lease-scenario.ts; for how the suite is split
// see the top of lease.test.ts.

import { describe, expect, it } from "vitest";

import {
  appendOperation,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  OWNER,
  projectId,
} from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario } from "./support/data-scenario.ts";
import type { LeasePolicy } from "./support/lease-scenario.ts";
import {
  backfillServerWrap,
  defaultPolicy,
  grantServer,
  requestLease,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

async function expect404(input: {
  readonly leasePolicy?: LeasePolicy;
  readonly scope?: readonly string[];
  readonly tokenOptions?: Parameters<typeof makeOidcToken>[0];
  readonly environmentId?: string;
  readonly skipGrant?: boolean;
}): Promise<void> {
  const dek = await createEnvironmentOk(fixture, ENV, "App");
  if (input.skipGrant !== true) {
    const scope = input.scope ?? [ENV];
    await grantServer({
      scope,
      ...(input.leasePolicy === undefined ? {} : { leasePolicy: input.leasePolicy }),
    });
    // Registering a server-directed wrap for an environment outside
    // the disclosure scope is itself a 422 (§12-6). In the out-of-scope
    // case, "no wrap but a grant exists" is the right precondition
    if (scope.includes(ENV)) {
      await backfillServerWrap(1, dek);
    }
  }
  const workload = await workloadKeyPair();
  const response = await requestLease({
    oidcToken: await makeOidcToken(input.tokenOptions),
    ephemeralPubHex: workload.publicKeyHex,
    ...(input.environmentId === undefined ? {} : { environmentId: input.environmentId }),
  });
  expect(response.status).toBe(404);
}

describe("workload leases: authorization and existence hiding (§14-1 / §11-2 — a uniform 404)", () => {
  it("hides a project with no server grant", async () => {
    await expect404({ skipGrant: true });
  });

  it("hides an empty lease policy (grant allows wrap registration only — CRYPTO_SPEC §6.2)", async () => {
    await expect404({ leasePolicy: [] });
  });

  it("fails closed when a matching policy element has no claim constraints", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: LEASE_AUDIENCE,
          claimConstraints: [],
        },
      ],
    });
  });

  it("hides an issuer mismatch in the policy", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: "https://gitlab.example",
          audience: LEASE_AUDIENCE,
          claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
        },
      ],
    });
  });

  it("hides an audience mismatch in the policy", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: "https://other.example",
          claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
        },
      ],
    });
  });

  it("hides a claim-constraint mismatch (different branch)", async () => {
    await expect404({
      tokenOptions: { subject: "repo:maruhi-test/demo:ref:refs/heads/feature-x" },
    });
  });

  it("hides an environment outside the disclosure scope", async () => {
    await expect404({ scope: ["env-other-0002"] });
  });

  it("hides an unknown project entirely (and writes no audit row)", async () => {
    const workload = await workloadKeyPair();
    const other = "f".repeat(64);
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
      project: other,
    });
    expect(response.status).toBe(404);
    // No audit row is created on the uninitialized DO (blocking a bloating DoS from the unauthenticated path)
    const rows = await queryProjectDo(other, "SELECT COUNT(*) AS n FROM audit_events");
    expect(rows[0]?.["n"]).toBe(0);
  });

  it("hides a deleted environment that is still inside the disclosure scope", async () => {
    // An environment inside the scope but already tombstoned
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({ scope: [ENV] });
    await backfillServerWrap(1, dek);
    const deleted = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(deleted.status).toBe(204);
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(404);
  });

  it("returns a byte-identical 404 body for every cause (the core of existence hiding)", async () => {
    // Watching only the status code would not detect a field added to
    // one branch in the future. Pin that even the bodies are identical,
    // in a single test.
    //
    // **Take the 4 branches separately**: an empty lease_policy makes
    // policy-mismatch settle first, never reaching
    // scope-out-of-range / environment-not-found — the same path's body
    // collected twice. Set a real policy and split the branches on the
    // token and requested-environment sides. Which branches were taken
    // is checked after the fact via lease_denied's reason (a silent
    // degeneration fails)
    const workload = await workloadKeyPair();
    const bodyOf = async (
      input: {
        readonly environmentId?: string;
        readonly subject?: string;
        readonly project?: string;
      } = {},
    ): Promise<string> => {
      const response = await requestLease({
        oidcToken: await makeOidcToken(
          input.subject === undefined ? {} : { subject: input.subject },
        ),
        ephemeralPubHex: workload.publicKeyHex,
        ...(input.environmentId === undefined ? {} : { environmentId: input.environmentId }),
        ...(input.project === undefined ? {} : { project: input.project }),
      });
      expect(response.status).toBe(404);
      return response.text();
    };

    // (a) An unknown project. **A different DO** is hit, so no audit remains (excluded from the comparison below)
    const unknownProject = "f".repeat(64);
    const bodies = [await bodyOf({ project: unknownProject })];

    // (b) No grant
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    bodies.push(await bodyOf());

    // A real policy + a scope containing "ENV and an uncreated environment ID"
    const uncreated = "env-in-scope-uncreated";
    await grantServer({ scope: [ENV, uncreated] });
    await backfillServerWrap(1, dek);

    // (c) A policy mismatch (a subject on a different branch)
    bodies.push(await bodyOf({ subject: "repo:maruhi-test/demo:ref:refs/heads/feature-x" }));
    // (d) An out-of-scope environment (the policy does match)
    bodies.push(await bodyOf({ environmentId: "env-out-of-scope-0009" }));
    // (e) An in-scope but uncreated environment
    bodies.push(await bodyOf({ environmentId: uncreated }));

    // The body carries only the echo of the caller's own input
    // (projectId). Only (a) used a different ID, so check that every
    // case but that one is identical
    expect(JSON.parse(bodies[0] ?? "{}")).toEqual({
      _tag: "ProjectNotFound",
      projectId: unknownProject,
    });
    expect(new Set(bodies.slice(1)).size).toBe(1);
    expect(JSON.parse(bodies[1] ?? "{}")).toEqual({ _tag: "ProjectNotFound", projectId });

    // Confirm via the audit that the 4 branches really were taken separately
    const denied = await queryProjectDo(
      projectId,
      "SELECT payload FROM audit_events WHERE event = 'server.lease_denied' ORDER BY seq",
    );
    const reasons = denied.map(
      (row) => (JSON.parse(String(row["payload"])) as { reason: string }).reason,
    );
    expect(reasons).toEqual([
      "no-grant",
      "policy-mismatch",
      "scope-out-of-range",
      "environment-not-found",
    ]);
  });

  it("authorizes when any policy element matches (existential — §14-1)", async () => {
    // Even with a non-matching element first, a later matching element authorizes
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await grantServer({
      scope: [ENV],
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: LEASE_AUDIENCE,
          claimConstraints: [{ claimName: "sub", claimValue: "repo:other/repo:ref:refs/heads/x" }],
        },
        ...defaultPolicy(),
      ],
    });
    await backfillServerWrap(1, dek);
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
  });

  it("requires every claim constraint of the matching element (AND)", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: LEASE_AUDIENCE,
          claimConstraints: [
            { claimName: "sub", claimValue: LEASE_SUBJECT },
            { claimName: "environment", claimValue: "production" },
          ],
        },
      ],
    });
  });

  it("never coerces non-string claims into a match", async () => {
    await expect404({
      leasePolicy: [
        {
          issuerUrl: OIDC_ISSUER,
          audience: LEASE_AUDIENCE,
          claimConstraints: [{ claimName: "run_number", claimValue: "42" }],
        },
      ],
      tokenOptions: { claims: { run_number: 42 } },
    });
  });

  it("stops leasing after revoke_server (the §7 revocation)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer({ scope: [ENV] });
    await backfillServerWrap(1, dek);
    const workload = await workloadKeyPair();
    expect(
      (
        await requestLease({
          oidcToken: await makeOidcToken(),
          ephemeralPubHex: workload.publicKeyHex,
        })
      ).status,
    ).toBe(200);

    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: fpHex },
    });
    const after = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(after.status).toBe(404);
  });

  it("records lease_denied with the reason and claims_digest, but no external identifier", async () => {
    await expect404({ leasePolicy: [] });
    const rows = await queryProjectDo(
      projectId,
      "SELECT actor_type, actor_user_id, actor_key_fingerprint, payload FROM audit_events WHERE event = 'server.lease_denied'",
    );
    expect(rows.length).toBe(1);
    // The actor is system (an external workload holds no identity on maruhi — §3.5)
    expect(rows[0]?.["actor_type"]).toBe("system");
    expect(rows[0]?.["actor_user_id"]).toBeNull();
    expect(rows[0]?.["actor_key_fingerprint"]).toBeNull();
    const payload = JSON.parse(String(rows[0]?.["payload"])) as Record<string, unknown>;
    expect(payload["reason"]).toBe("policy-mismatch");
    expect(typeof payload["claimsDigest"]).toBe("string");
    // External identifiers (sub / repo name) are not written (§14-4 / AUDIT_SPEC §1-2)
    expect(JSON.stringify(payload)).not.toContain("maruhi-test/demo");
  });
});
