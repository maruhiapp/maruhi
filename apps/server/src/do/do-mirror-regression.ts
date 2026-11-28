import {
  CHECKPOINT_TABLE,
  ENVIRONMENTS_TABLE,
  hasTable,
  malformed,
  MANIFEST_TABLE,
  stagedCount,
  stagedRowOf,
  stagingOf,
  VARIABLES_TABLE,
} from "./do-mirror-state.ts";

function stagedEnvTombstoned(sql: SqlStorage, environmentId: string): boolean {
  const staging = stagingOf(ENVIRONMENTS_TABLE);
  if (!hasTable(sql, staging)) {
    return false;
  }
  const row = sql
    .exec(`SELECT deleted_at FROM ${staging} WHERE environment_id = ?`, environmentId)
    .toArray()[0];
  return row !== undefined && row["deleted_at"] !== null;
}

function verifyRowsPreserved(
  sql: SqlStorage,
  table: string,
  keyColumns: readonly string[],
  exempt: string,
): void {
  const staging = stagingOf(table);
  const notExempt = exempt === "" ? "" : ` AND NOT (${exempt})`;
  if (!hasTable(sql, staging)) {
    const missing = sql
      .exec(`SELECT COUNT(*) AS n FROM ${table} AS own WHERE 1 = 1${notExempt}`)
      .one()["n"];
    if (Number(missing) !== 0) {
      throw malformed();
    }
    return;
  }
  const columns = sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
  const join = keyColumns.map((column) => `theirs.${column} = own.${column}`).join(" AND ");
  const differs = columns
    .filter((column) => !keyColumns.includes(column))
    .map((column) => `own.${column} IS NOT theirs.${column}`)
    .join(" OR ");
  const rewritten = sql
    .exec(
      `SELECT COUNT(*) AS n FROM ${table} AS own LEFT JOIN ${staging} AS theirs ON ${join} WHERE (theirs.${keyColumns[0]} IS NULL OR ${differs})${notExempt}`,
    )
    .one()["n"];
  if (Number(rewritten) !== 0) {
    throw malformed();
  }
}

function envCascadeExempt(sql: SqlStorage): string {
  const staging = stagingOf(ENVIRONMENTS_TABLE);
  return hasTable(sql, staging)
    ? `EXISTS (SELECT 1 FROM ${staging} AS se WHERE se.environment_id = own.environment_id AND se.deleted_at IS NOT NULL)`
    : "";
}

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the projection-regression checklist over the staged tables; each branch is one refusal condition, and splitting the checklist would obscure it
export function verifyProjectionRegression(sql: SqlStorage): void {
  const envExempt = envCascadeExempt(sql);
  verifyRowsPreserved(
    sql,
    "environment_meta_statements",
    ["environment_id", "meta_version"],
    envExempt,
  );
  verifyRowsPreserved(
    sql,
    "variable_meta_statements",
    ["environment_id", "variable_id", "meta_version"],
    envExempt,
  );
  const varStaging = stagingOf(VARIABLES_TABLE);
  const varTomb = hasTable(sql, varStaging)
    ? `EXISTS (SELECT 1 FROM ${varStaging} AS sv WHERE sv.environment_id = own.environment_id AND sv.variable_id = own.variable_id AND sv.deleted_at IS NOT NULL)`
    : "";
  const varExempt = [envExempt, varTomb].filter((part) => part !== "").join(" OR ");
  verifyRowsPreserved(
    sql,
    "variable_versions",
    ["environment_id", "variable_id", "version"],
    varExempt,
  );
  const envStaging = stagingOf(ENVIRONMENTS_TABLE);
  if (!hasTable(sql, envStaging)) {
    if (stagedCount(sql, ENVIRONMENTS_TABLE) !== 0 || liveCount(sql, ENVIRONMENTS_TABLE) !== 0) {
      throw malformed();
    }
  } else {
    const regressed = sql
      .exec(
        `SELECT COUNT(*) AS n FROM ${ENVIRONMENTS_TABLE} AS own LEFT JOIN ${envStaging} AS theirs ON theirs.environment_id = own.environment_id WHERE theirs.environment_id IS NULL OR theirs.latest_meta_version < own.latest_meta_version`,
      )
      .one()["n"];
    if (Number(regressed) !== 0) {
      throw malformed();
    }
    if (hasTable(sql, varStaging)) {
      const badVars = sql
        .exec(
          `SELECT COUNT(*) AS n FROM ${VARIABLES_TABLE} AS own LEFT JOIN ${varStaging} AS theirs ON theirs.environment_id = own.environment_id AND theirs.variable_id = own.variable_id WHERE (theirs.variable_id IS NULL AND NOT (${envExempt === "" ? "0" : envExempt})) OR theirs.latest_meta_version < own.latest_meta_version OR theirs.latest_version < own.latest_version`,
        )
        .one()["n"];
      if (Number(badVars) !== 0) {
        throw malformed();
      }
    } else if (liveCount(sql, VARIABLES_TABLE) !== 0) {
      throw malformed();
    }
  }
  verifyManifestRegression(sql);
  verifyCheckpointRegression(sql);
}

function liveCount(sql: SqlStorage, table: string): number {
  return Number(sql.exec(`SELECT COUNT(*) AS n FROM ${table}`).one()["n"]);
}

function verifyManifestRegression(sql: SqlStorage): void {
  const live = sql.exec(`SELECT * FROM ${MANIFEST_TABLE}`).toArray();
  for (const row of live) {
    const environmentId = String(row["environment_id"]);
    const staged = stagedRowOf(sql, MANIFEST_TABLE, environmentId);
    if (staged === undefined) {
      if (!stagedEnvTombstoned(sql, environmentId)) {
        throw malformed();
      }
      continue;
    }
    if (
      Number(staged["manifest_version"]) < Number(row["manifest_version"]) ||
      Number(staged["epoch"]) < Number(row["epoch"]) ||
      (Number(staged["manifest_version"]) === Number(row["manifest_version"]) &&
        String(staged["signed_bytes_hash_hex"]) !== String(row["signed_bytes_hash_hex"]))
    ) {
      throw malformed();
    }
  }
}

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the checkpoint half of the projection-regression checklist; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyCheckpointRegression(sql: SqlStorage): void {
  const live = sql.exec(`SELECT * FROM ${CHECKPOINT_TABLE}`).toArray();
  for (const row of live) {
    const environmentId = String(row["environment_id"]);
    const staged = stagedRowOf(sql, CHECKPOINT_TABLE, environmentId);
    if (staged === undefined) {
      if (!stagedEnvTombstoned(sql, environmentId)) {
        throw malformed();
      }
      continue;
    }
    if (
      Number(staged["chain_seq"]) < Number(row["chain_seq"]) ||
      Number(staged["manifest_version"]) < Number(row["manifest_version"]) ||
      Number(staged["epoch"]) < Number(row["epoch"]) ||
      (Number(staged["chain_seq"]) === Number(row["chain_seq"]) &&
        (String(staged["entry_hash_hex"]) !== String(row["entry_hash_hex"]) ||
          Number(staged["epoch"]) !== Number(row["epoch"]) ||
          Number(staged["manifest_version"]) !== Number(row["manifest_version"]) ||
          String(staged["manifest_sig_hash_hex"]) !== String(row["manifest_sig_hash_hex"]) ||
          String(staged["values_digest_hex"]) !== String(row["values_digest_hex"])))
    ) {
      throw malformed();
    }
    if (String(staged["values_digest_hex"]) === String(row["values_digest_hex"])) {
      verifySnapshotValuesPreserved(sql, environmentId);
    }
  }
}

function verifySnapshotValuesPreserved(sql: SqlStorage, environmentId: string): void {
  const table = "checkpoint_snapshot_values";
  const staging = stagingOf(table);
  if (!hasTable(sql, staging)) {
    const missing = sql
      .exec(`SELECT COUNT(*) AS n FROM ${table} WHERE environment_id = ?`, environmentId)
      .one()["n"];
    if (Number(missing) !== 0) {
      throw malformed();
    }
    return;
  }
  const rewritten = sql
    .exec(
      `SELECT COUNT(*) AS n FROM ${table} AS own LEFT JOIN ${staging} AS theirs ON theirs.environment_id = own.environment_id AND theirs.variable_id = own.variable_id WHERE own.environment_id = ? AND (theirs.variable_id IS NULL OR own.version IS NOT theirs.version OR own.value_sig_hash_hex IS NOT theirs.value_sig_hash_hex)`,
      environmentId,
    )
    .one()["n"];
  if (Number(rewritten) !== 0) {
    throw malformed();
  }
  const extra = sql
    .exec(
      `SELECT COUNT(*) AS n FROM ${staging} AS theirs LEFT JOIN ${table} AS own ON own.environment_id = theirs.environment_id AND own.variable_id = theirs.variable_id WHERE theirs.environment_id = ? AND own.variable_id IS NULL`,
      environmentId,
    )
    .one()["n"];
  if (Number(extra) !== 0) {
    throw malformed();
  }
}
