// The Effect service implementation of the D1 repositories (AUTH_SPEC
// §2; ADR-0006).
//
// - Drizzle types and queries are confined to this file (inside the
//   db.package boundary). The public shapes are domain types
//   (../auth-domain.ts) and Effect only
// - A D1 failure (connection, SQL error) is treated as a defect
//   (Effect.promise). Only the domain-expected branches (no such row,
//   a unique-constraint conflict) are expressed as values
// - The settled decision to adopt Drizzle is session 06: classic
//   drizzle-orm/d1 was adopted. The effect-d1 driver at rc.4 did not
//   support transaction / batch, so getOrCreateUser (§1-5), which needs
//   atomicity, could not stand. D1's atomic batch is used

import { drizzle } from "drizzle-orm/d1";
import { Context } from "effect";

import { D1AuditRepo, makeD1AuditRepo } from "./audit.ts";
import { CliFlowRepo, makeCliFlowRepo } from "./cli-flows.ts";
import { DeviceRepo, makeDeviceRepo } from "./devices.ts";
import { FlowSigningKeyRepo, makeFlowSigningKeyRepo } from "./flow-signing-keys.ts";
import { IdentityRepo, makeIdentityRepo } from "./identities.ts";
import { InviteRepo, makeInviteRepo } from "./invites.ts";
import { KeyWrapRepo, makeKeyWrapRepo } from "./key-wraps.ts";
import { makeOpsRepo, OpsRepo } from "./ops.ts";
import { makeOrgRepo, OrgRepo } from "./orgs.ts";
import { makeProjectRepo, ProjectRepo } from "./projects.ts";
import { makeRecoveryRepo, RecoveryRepo } from "./recovery.ts";
import { makeSessionRepo, SessionRepo } from "./sessions.ts";
import { makeTokenRepo, TokenRepo } from "./tokens.ts";

export { isUniqueConflict } from "./errors.ts";

// ---------------------------------------------------------------------------
// The bundle: build the Context of the whole repository set from a D1
// binding
// ---------------------------------------------------------------------------

export type DbServices =
  | IdentityRepo
  | SessionRepo
  | TokenRepo
  | OrgRepo
  | ProjectRepo
  | RecoveryRepo
  | InviteRepo
  | FlowSigningKeyRepo
  | CliFlowRepo
  | D1AuditRepo
  | OpsRepo
  | KeyWrapRepo
  | DeviceRepo;

/** Builds the set of repository services from a D1 binding (once at worker startup). */
export function makeDbServices(d1: D1Database): Context.Context<DbServices> {
  const db = drizzle(d1);
  // The master key-wrap ledger (AUTH_SPEC §13-6–13-10 — KL3). The
  // recovery-code fetch window also uses this summed window (§13-8)
  const keyWraps = makeKeyWrapRepo(db);
  return Context.make(IdentityRepo, makeIdentityRepo(db)).pipe(
    Context.add(SessionRepo, makeSessionRepo(db)),
    Context.add(TokenRepo, makeTokenRepo(db)),
    Context.add(OrgRepo, makeOrgRepo(db)),
    Context.add(ProjectRepo, makeProjectRepo(db)),
    Context.add(RecoveryRepo, makeRecoveryRepo(db, keyWraps)),
    Context.add(KeyWrapRepo, keyWraps),
    Context.add(InviteRepo, makeInviteRepo(db)),
    Context.add(FlowSigningKeyRepo, makeFlowSigningKeyRepo(db)),
    Context.add(CliFlowRepo, makeCliFlowRepo(db)),
    Context.add(D1AuditRepo, makeD1AuditRepo(db)),
    // Operations (H3 — hosted-ops.md §6): counters, evacuation
    // records, state kv
    Context.add(OpsRepo, makeOpsRepo(db)),
    // The device registry and device-add requests (AUTH_SPEC §13-11 —
    // DK K3. advisory)
    Context.add(DeviceRepo, makeDeviceRepo(db)),
  );
}
