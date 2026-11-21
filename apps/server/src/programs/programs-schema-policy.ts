import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { DataActor, SchemaPolicy } from "../data.package/index.ts";
import { dataEvent, DataStore, requireMemberState } from "../data.package/index.ts";
import type { StateCache } from "../do/chain-store.ts";
import { ensureStorageAdmitsGrowth } from "../storage-guard.ts";

export const getSchemaPolicyProgram = Effect.fn("programs-schema-policy.getSchemaPolicyProgram")(
  function* (actor: DataActor, cache: StateCache) {
    yield* requireMemberState(actor.userId, "reader", cache);
    const store = yield* DataStore;
    return { schemaPolicy: yield* store.schemaPolicy };
  },
);

export const setSchemaPolicyProgram = Effect.fn("programs-schema-policy.setSchemaPolicyProgram")(
  function* (actor: DataActor, schemaPolicy: SchemaPolicy, cache: StateCache) {
    yield* requireMemberState(actor.userId, "admin", cache);
    yield* ensureStorageAdmitsGrowth;
    const store = yield* DataStore;
    const previous = yield* store.schemaPolicy;
    if (previous === schemaPolicy) {
      return;
    }
    const audit = yield* AuditStore;
    const now = yield* Clock.currentTimeMillis;
    yield* Effect.sync(() => {
      store.write.setSchemaPolicy(schemaPolicy);
      audit.appendSync(
        dataEvent(actor, now, {
          event: "project.schema_policy_changed",
          payload: { previous, next: schemaPolicy },
        }),
      );
    });
  },
);
