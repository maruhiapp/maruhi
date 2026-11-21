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

export { D1FailureError, D1UniqueConflictError, tryD1 } from "./errors.ts";

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

export function makeDbServices(d1: D1Database): Context.Context<DbServices> {
  const db = drizzle(d1);
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
    Context.add(OpsRepo, makeOpsRepo(db)),
    Context.add(DeviceRepo, makeDeviceRepo(db)),
  );
}
