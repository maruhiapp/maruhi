// ES K3 — what scope does not change (design record
// docs/notes/es-design.md §9 / §1-4):
//   - The lease path (AUTH_SPEC §14-1): member scopes play no role in
//     leasing. Environment restriction is carried only by the grant's
//     scope_environments
//   - Visibility classes (AUDIT_SPEC §6): class-1 events and
//     rotation-required flags of out-of-scope environments are visible to
//     listed members too (the visibility predicate takes no environment
//     axis)

import { describe, expect, it } from "vitest";

import { fetchEvents } from "./support/audit-read-scenario.ts";
import { addMemberOperation } from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  requestJson,
  seedMemberToken,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import {
  backfillServerWrap,
  grantServer,
  requestLease,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { makeOidcToken } from "./support/lease.ts";

registerDataScenario();

const DEV = "user-devmember-0010";
const DEVADMIN = "user-devadmin-0011";
const OTHER = "env-other-0002";

describe("the lease path is unchanged (AUTH_SPEC §14-1)", () => {
  it("a lease is decided by the grant's scope alone even with members in listed{} / listed{OTHER}", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, OTHER, "Other");
    // A member whose scope does not contain ENV (not in the complete set
    // either)
    await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member", [OTHER]));
    await grantServer({ scope: [ENV] });
    await backfillServerWrap(1, dek);
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
  });
});

describe("visibility classes are unchanged (AUDIT_SPEC §6)", () => {
  it("var.* / env.* / chain.* of out-of-scope environments and rotation-required flags are visible to listed members too", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, OTHER, "Other");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await seedMemberToken(fixture, DEV, 9010);
    // DEV has only OTHER — ENV is out of scope
    await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member", [OTHER]));
    // Flags against variables of ENV (out of DEV's scope): surfaced by
    // removing the all member
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });

    const { status, events } = await fetchEvents(token(DEV), { limit: "200" });
    expect(status).toBe(200);
    const names = events.map((event) => event.event);
    expect(names).toEqual(
      expect.arrayContaining([
        "chain.environment_created",
        "env.created",
        "var.created",
        "chain.member_removed",
        "rotation.recommended",
      ]),
    );
    expect(
      events.some((event) => event.event === "var.created" && event.environmentId === ENV),
    ).toBe(true);
    const flags = await requestJson("GET", "/rotation/flags", token(DEV));
    expect(flags.status).toBe(200);
    const body = (await flags.json()) as { flags: { environmentId: string }[] };
    expect(body.flags.some((flag) => flag.environmentId === ENV)).toBe(true);
  });

  it("dismissing a rotation-required flag is an admin's call regardless of scope (§3.3 / §4.1-5 — the only non-scope path carrying environment coordinates)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, OTHER, "Other");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await seedMemberToken(fixture, DEVADMIN, 9011);
    await appendOperation(fixture, OWNER, addMemberOperation(DEVADMIN, "admin", [OTHER]));
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    // ENV is out of DEVADMIN's scope, but a dismissal (admin x admin scope)
    // goes through
    const dismissed = await requestJson("POST", "/rotation/dismissals", token(DEVADMIN), {
      targets: [{ environmentId: ENV, variableId: VAR }],
    });
    expect(dismissed.status).toBe(204);
    const flags = await requestJson("GET", "/rotation/flags", token(DEVADMIN));
    expect(((await flags.json()) as { flags: unknown[] }).flags).toHaveLength(0);
  });
});
