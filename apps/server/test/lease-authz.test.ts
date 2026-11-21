import { describe, expect, it } from "vite-plus/test";

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
    const tables = await queryProjectDo(
      other,
      "SELECT name FROM sqlite_master WHERE type = 'table'",
    );
    expect(tables).toEqual([]);
  });

  it("hides a deleted environment that is still inside the disclosure scope", async () => {
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

    const unknownProject = "f".repeat(64);
    const bodies = [await bodyOf({ project: unknownProject })];

    const dek = await createEnvironmentOk(fixture, ENV, "App");
    bodies.push(await bodyOf());

    const uncreated = "env-in-scope-uncreated";
    await grantServer({ scope: [ENV, uncreated] });
    await backfillServerWrap(1, dek);

    bodies.push(await bodyOf({ subject: "repo:maruhi-test/demo:ref:refs/heads/feature-x" }));
    bodies.push(await bodyOf({ environmentId: "env-out-of-scope-0009" }));
    bodies.push(await bodyOf({ environmentId: uncreated }));

    expect(JSON.parse(bodies[0] ?? "{}")).toEqual({
      _tag: "ProjectNotFound",
      projectId: unknownProject,
    });
    expect(new Set(bodies.slice(1)).size).toBe(1);
    expect(JSON.parse(bodies[1] ?? "{}")).toEqual({ _tag: "ProjectNotFound", projectId });

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
    expect(rows[0]?.["actor_type"]).toBe("system");
    expect(rows[0]?.["actor_user_id"]).toBeNull();
    expect(rows[0]?.["actor_key_fingerprint"]).toBeNull();
    const payload = JSON.parse(String(rows[0]?.["payload"])) as Record<string, unknown>;
    expect(payload["reason"]).toBe("policy-mismatch");
    expect(typeof payload["claimsDigest"]).toBe("string");
    expect(JSON.stringify(payload)).not.toContain("maruhi-test/demo");
  });
});
