// Effect program for the project setting schemaPolicy
// (AUTH_SPEC §12-11).
//
// - Get: read scope (worker) × chain role reader or above (here)
// - Set: admin scope (worker) × chain role admin or above (here).
//   204. A change writes project.schema_policy_changed (AUDIT_SPEC
//   §3.3 — payload = old value / new value, actor = type=user; being a
//   setting operation without a signature, it carries no key FP)
// - The acceptance-check side (programs-variable.ts / verify-meta.ts)
//   reads store.schemaPolicy under the same permit — no race window
//   against a change (§12-11)

import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { DataActor, SchemaPolicy } from "../data/data-plane.ts";
import { dataEvent, requireMemberState } from "../data/data-plane.ts";
import { DataStore } from "../data/data-store.ts";
import type { StateCache } from "../do/chain-store.ts";
import { ensureStorageAdmitsGrowth } from "../storage-guard.ts";

export const getSchemaPolicyProgram = (actor: DataActor, cache: StateCache) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "reader", cache);
    const store = yield* DataStore;
    return { schemaPolicy: yield* store.schemaPolicy };
  });

export const setSchemaPolicyProgram = (
  actor: DataActor,
  schemaPolicy: SchemaPolicy,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "admin", cache);
    // The DO storage-total guard (AUTH_SPEC §12-8): a settings change
    // is not a content-growth surface, but it is not needed for
    // evacuation, release, or security remediation either, and each
    // change adds an audit row (unbounded under admin iteration), so it
    // is included among the refused. Get (getSchemaPolicyProgram) is a
    // read = passes even under refusal
    yield* ensureStorageAdmitsGrowth;
    const store = yield* DataStore;
    const previous = yield* store.schemaPolicy;
    if (previous === schemaPolicy) {
      // An idempotent equal-value PUT stays a 204 and records no
      // audit (a transition that did not change anything is not
      // written to the "changed" event — AUDIT_SPEC §3.3's payload is
      // old value / new value)
      return;
    }
    const audit = yield* AuditStore;
    const now = yield* Clock.currentTimeMillis;
    // The settings upsert and the audit row are written in the same
    // synchronous block (atomicity)
    yield* Effect.sync(() => {
      store.write.setSchemaPolicy(schemaPolicy);
      audit.appendSync(
        dataEvent(actor, now, "project.schema_policy_changed", {
          payload: { previous, next: schemaPolicy },
        }),
      );
    });
  });
