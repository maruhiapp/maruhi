// The project-settings reads of the data store (AUTH_SPEC §12-11 —
// currently only schemaPolicy) — assembled into DataStoreShape by
// dataStoreLayer in data-store.ts.

import { Effect } from "effect";

import type { SchemaPolicy } from "./data-plane.ts";
import { stringColumn } from "./data-store-rows.ts";

/**
 * Project settings (AUTH_SPEC §12-11 — currently only schemaPolicy). No
 * row = the default disabled. An unknown stored value is a defect as
 * storage corruption (the same discipline as storedSuite — never
 * silently re-read as the default).
 */
export const makeSettingsQueries = (sql: SqlStorage) => ({
  schemaPolicy: Effect.sync((): SchemaPolicy => {
    const row = sql.exec("SELECT schema_policy FROM project_settings WHERE id = 1").toArray()[0];
    if (row === undefined) {
      return "disabled";
    }
    const policy = stringColumn(row, "schema_policy");
    if (policy !== "disabled" && policy !== "enabled" && policy !== "locked") {
      throw new Error("unexpected schema_policy in stored project settings row");
    }
    return policy;
  }),
});
