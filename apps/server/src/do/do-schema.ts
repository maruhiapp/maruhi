const PROJECT_DO_DDL = [
  `CREATE TABLE chain_entries (
     seq INTEGER PRIMARY KEY,
     entry_json TEXT NOT NULL,
     entry_hash_hex TEXT NOT NULL,
     canonical_bytes INTEGER NOT NULL
   )`,
  `CREATE TABLE environments (
     environment_id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     latest_meta_version INTEGER NOT NULL,
     created_at INTEGER NOT NULL,
     deleted_at INTEGER
   )`,
  `CREATE TABLE variables (
     environment_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     name TEXT NOT NULL,
     latest_meta_version INTEGER NOT NULL,
     latest_version INTEGER NOT NULL,
     created_at INTEGER NOT NULL,
     deleted_at INTEGER,
     PRIMARY KEY (environment_id, variable_id)
   )`,
  `CREATE TABLE variable_meta_statements (
     environment_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     meta_version INTEGER NOT NULL,
     suite TEXT NOT NULL,
     name TEXT NOT NULL,
     status TEXT NOT NULL,
     prev_meta_sig_hash_hex TEXT NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     signature_hex TEXT NOT NULL,
     signed_bytes_hash_hex TEXT NOT NULL,
     author_user_id TEXT NOT NULL,
     author_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     layout_version INTEGER NOT NULL DEFAULT 1,
     var_type TEXT,
     required TEXT,
     description TEXT,
     max_age_days TEXT,
     PRIMARY KEY (environment_id, variable_id, meta_version)
   )`,
  `CREATE TABLE environment_meta_statements (
     environment_id TEXT NOT NULL,
     meta_version INTEGER NOT NULL,
     suite TEXT NOT NULL,
     name TEXT NOT NULL,
     status TEXT NOT NULL,
     prev_meta_sig_hash_hex TEXT NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     signature_hex TEXT NOT NULL,
     signed_bytes_hash_hex TEXT NOT NULL,
     author_user_id TEXT NOT NULL,
     author_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     PRIMARY KEY (environment_id, meta_version)
   )`,
  `CREATE TABLE variable_versions (
     environment_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     version INTEGER NOT NULL,
     suite TEXT NOT NULL,
     epoch INTEGER NOT NULL,
     nonce_hex TEXT NOT NULL,
     ciphertext_hex TEXT NOT NULL,
     ciphertext_bytes INTEGER NOT NULL,
     prev_value_sig_hash_hex TEXT NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     signature_hex TEXT NOT NULL,
     signed_bytes_hash_hex TEXT NOT NULL,
     writer_user_id TEXT NOT NULL,
     writer_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     PRIMARY KEY (environment_id, variable_id, version)
   )`,
  `CREATE TABLE dek_wraps (
     environment_id TEXT NOT NULL,
     epoch INTEGER NOT NULL,
     recipient_user_id TEXT NOT NULL,
     suite TEXT NOT NULL,
     recipient_enc_pub_hex TEXT NOT NULL,
     enc_hex TEXT NOT NULL,
     ciphertext_hex TEXT NOT NULL,
     signature_hex TEXT NOT NULL,
     signer_user_id TEXT NOT NULL,
     signer_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     recipient_class TEXT NOT NULL DEFAULT 'member',
     PRIMARY KEY (environment_id, epoch, recipient_user_id, recipient_enc_pub_hex)
   )`,
  `CREATE INDEX dw_recipient ON dek_wraps (recipient_user_id, recipient_class)`,
  `CREATE TABLE audit_events (
     seq INTEGER PRIMARY KEY,
     server_ts INTEGER NOT NULL,
     client_ts INTEGER,
     event TEXT NOT NULL,
     actor_type TEXT NOT NULL,
     actor_user_id TEXT,
     actor_key_fingerprint TEXT,
     actor_api_token_id TEXT,
     target_user_id TEXT,
     target_key_fingerprint TEXT,
     environment_id TEXT,
     variable_id TEXT,
     epoch INTEGER,
     version INTEGER,
     chain_seq INTEGER,
     payload TEXT,
     row_id TEXT NOT NULL
   )`,
  `CREATE INDEX ae_var ON audit_events (variable_id, environment_id, seq)`,
  `CREATE INDEX ae_actor ON audit_events (actor_user_id, seq)`,
  `CREATE INDEX ae_event ON audit_events (event, seq)`,
  `CREATE UNIQUE INDEX ae_row_id ON audit_events (row_id)`,
  `CREATE INDEX ae_target ON audit_events (target_user_id, seq) WHERE target_user_id IS NOT NULL`,
  `CREATE INDEX ae_target_fp ON audit_events (target_key_fingerprint, seq) WHERE target_key_fingerprint IS NOT NULL`,
  `CREATE INDEX ae_actor_fp ON audit_events (actor_key_fingerprint, seq) WHERE actor_key_fingerprint IS NOT NULL`,
  `CREATE TABLE lease_windows (
     kind TEXT PRIMARY KEY,
     window_start INTEGER NOT NULL,
     count INTEGER NOT NULL
   )`,
  `CREATE TABLE lease_bindings (
     binding_key_hex TEXT PRIMARY KEY,
     ephemeral_pub_hex TEXT NOT NULL,
     expires_at INTEGER NOT NULL
   )`,
  `CREATE TABLE environment_manifests (
     environment_id TEXT PRIMARY KEY,
     manifest_version INTEGER NOT NULL,
     suite TEXT NOT NULL,
     epoch INTEGER NOT NULL,
     variables_digest_hex TEXT NOT NULL,
     env_meta_version INTEGER NOT NULL,
     env_meta_sig_hash_hex TEXT NOT NULL,
     prev_manifest_sig_hash_hex TEXT NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     signature_hex TEXT NOT NULL,
     signed_bytes_hash_hex TEXT NOT NULL,
     issuer_user_id TEXT NOT NULL,
     issuer_key_fingerprint TEXT NOT NULL,
     created_at INTEGER NOT NULL
   )`,
  `CREATE TABLE environment_checkpoints (
     environment_id TEXT PRIMARY KEY,
     chain_seq INTEGER NOT NULL,
     entry_hash_hex TEXT NOT NULL,
     epoch INTEGER NOT NULL,
     manifest_version INTEGER NOT NULL,
     manifest_sig_hash_hex TEXT NOT NULL,
     values_digest_hex TEXT NOT NULL,
     updated_at INTEGER NOT NULL
   )`,
  `CREATE TABLE checkpoint_snapshot_values (
     environment_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     version INTEGER NOT NULL,
     value_sig_hash_hex TEXT NOT NULL,
     PRIMARY KEY (environment_id, variable_id)
   )`,
  `CREATE TABLE audit_head_hashes (
     seq INTEGER PRIMARY KEY,
     head_hash_hex TEXT NOT NULL
   )`,
  `CREATE INDEX ahh_hash ON audit_head_hashes (head_hash_hex)`,
  `CREATE TABLE head_attestations (
     attester_user_id TEXT NOT NULL,
     attester_key_fingerprint TEXT NOT NULL,
     suite TEXT NOT NULL,
     chain_head_seq INTEGER NOT NULL,
     chain_head_hash_hex TEXT NOT NULL,
     signature_hex TEXT NOT NULL,
     accepted_at INTEGER NOT NULL,
     PRIMARY KEY (attester_user_id, attester_key_fingerprint)
   )`,
  `CREATE TABLE attestation_windows (
     attester_user_id TEXT PRIMARY KEY,
     window_start INTEGER NOT NULL,
     count INTEGER NOT NULL
   )`,
  `CREATE TABLE project_settings (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     schema_policy TEXT NOT NULL
   )`,
  `CREATE TABLE rotation_proposals (
     proposal_id TEXT PRIMARY KEY,
     environment_id TEXT NOT NULL,
     connector TEXT NOT NULL,
     facts_json TEXT NOT NULL,
     claims_digest_hex TEXT NOT NULL,
     grant_chain_seq INTEGER NOT NULL,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL
   )`,
  `CREATE TABLE rotation_proposal_variables (
     proposal_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     base_version INTEGER NOT NULL,
     position INTEGER NOT NULL,
     PRIMARY KEY (proposal_id, variable_id)
   )`,
  `CREATE TABLE rotation_proposal_wraps (
     proposal_id TEXT NOT NULL,
     variable_id TEXT NOT NULL,
     recipient_user_id TEXT NOT NULL,
     recipient_enc_pub_hex TEXT NOT NULL,
     enc_hex TEXT NOT NULL,
     ciphertext_hex TEXT NOT NULL,
     PRIMARY KEY (proposal_id, variable_id, recipient_user_id, recipient_enc_pub_hex)
   )`,
  `CREATE TABLE mirror_state (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     source_origin TEXT NOT NULL,
     marked_at INTEGER NOT NULL,
     expected_sequence INTEGER NOT NULL,
     staging_table TEXT,
     last_synced_at INTEGER,
     last_head_seq INTEGER,
     last_head_hash_hex TEXT,
     last_audit_seq INTEGER,
     last_attestation_mark INTEGER NOT NULL,
     last_mutation_seq INTEGER
   )`,
  `CREATE TABLE mutation_state (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     seq INTEGER NOT NULL
   )`,
];

export interface ProjectDoMigration {
  readonly tables: readonly string[];
  readonly apply: (sql: SqlStorage) => void;
}

export interface ProjectDoMigrationPlan {
  readonly baseVersion: number;
  readonly base: ProjectDoMigration;
  readonly steps: readonly ProjectDoMigration[];
}

const PROJECT_DO_BASE_VERSION = 9;

const PROJECT_DO_BASE_TABLES: readonly string[] = [
  "chain_entries",
  "environments",
  "variables",
  "variable_meta_statements",
  "environment_meta_statements",
  "variable_versions",
  "dek_wraps",
  "audit_events",
  "lease_windows",
  "lease_bindings",
  "environment_manifests",
  "environment_checkpoints",
  "checkpoint_snapshot_values",
  "audit_head_hashes",
  "head_attestations",
  "attestation_windows",
  "project_settings",
  "rotation_proposals",
  "rotation_proposal_variables",
  "rotation_proposal_wraps",
];

export const PROJECT_DO_MIGRATIONS: ProjectDoMigrationPlan = {
  baseVersion: PROJECT_DO_BASE_VERSION,
  base: {
    tables: PROJECT_DO_BASE_TABLES,
    apply(sql) {
      for (const statement of PROJECT_DO_DDL) {
        sql.exec(statement);
      }
      const declared = new Set(PROJECT_DO_BASE_TABLES);
      const tracked = sql
        .exec("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .toArray()
        .map((row) => String(row["name"]))
        .filter((name) => declared.has(name) && isMutationTracked(name));
      for (const table of tracked) {
        for (const statement of mutationTriggers(table)) {
          sql.exec(statement);
        }
      }
      sql.exec(auditWriteTrigger());
    },
  },
  steps: [],
};

export const PROJECT_DO_LATEST_SCHEMA_VERSION =
  PROJECT_DO_MIGRATIONS.baseVersion + PROJECT_DO_MIGRATIONS.steps.length;

const AUDIT_WRITE_TRIGGER = "mutation_audit_events_write";

function readPathList(): string {
  return READ_PATH_AUDIT_EVENTS.map((event) => `'${event}'`).join(", ");
}

function auditWriteTrigger(): string {
  return `CREATE TRIGGER IF NOT EXISTS ${AUDIT_WRITE_TRIGGER} AFTER INSERT ON audit_events
         WHEN NEW.event NOT IN (${readPathList()})
         BEGIN
           INSERT INTO mutation_state (id, seq) VALUES (1, 1) ON CONFLICT(id) DO UPDATE SET seq = seq + 1;
         END`;
}

function ensureAuditWriteTrigger(sql: SqlStorage): void {
  const row = sql
    .exec("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?", AUDIT_WRITE_TRIGGER)
    .toArray()[0];
  if (
    row === undefined ||
    String(row["sql"]) !== auditWriteTrigger().replace("IF NOT EXISTS ", "")
  ) {
    sql.exec(`DROP TRIGGER IF EXISTS ${AUDIT_WRITE_TRIGGER}`);
    sql.exec(auditWriteTrigger());
  }
}

const READ_PATH_AUDIT_EVENTS: readonly string[] = [
  "var.read",
  "server.lease_issued",
  "server.lease_denied",
  "server.dek_unwrapped",
  "server.value_decrypted",
  "project.exported",
];

const MUTATION_UNTRACKED_TABLES: ReadonlySet<string> = new Set([
  "audit_events",
  "audit_head_hashes",
  "lease_windows",
  "lease_bindings",
  "attestation_windows",
  "mirror_state",
  "mutation_state",
  "schema_meta",
]);

function mutationTriggers(table: string): readonly string[] {
  return ["INSERT", "UPDATE", "DELETE"].map(
    (event) =>
      `CREATE TRIGGER IF NOT EXISTS mutation_${table}_${event.toLowerCase()} AFTER ${event} ON ${table}
       BEGIN
         INSERT INTO mutation_state (id, seq) VALUES (1, 1) ON CONFLICT(id) DO UPDATE SET seq = seq + 1;
       END`,
  );
}

export function isMutationTracked(table: string): boolean {
  return !MUTATION_UNTRACKED_TABLES.has(table);
}

export const PROJECT_DO_TABLES: readonly string[] = [
  ...PROJECT_DO_MIGRATIONS.base.tables,
  ...PROJECT_DO_MIGRATIONS.steps.flatMap((step) => step.tables),
];

export const PROJECT_DO_LOCAL_TABLES: readonly string[] = ["mirror_state", "mutation_state"];

const SCHEMA_META_DDL = `CREATE TABLE IF NOT EXISTS schema_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
)`;

export function projectDoInitialized(sql: SqlStorage): boolean {
  return (
    sql
      .exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chain_entries' LIMIT 1")
      .toArray().length > 0
  );
}

export function readProjectDoSchemaVersion(sql: SqlStorage): number {
  sql.exec(SCHEMA_META_DDL);
  const rows = sql.exec("SELECT version FROM schema_meta WHERE id = 1").toArray();
  const row = rows[0];
  if (row === undefined) {
    return 0;
  }
  const version = Number(row.version);
  if (!Number.isInteger(version) || version < 0) {
    throw new Error(`project DO schema_meta.version is corrupt: ${String(row.version)}`);
  }
  return version;
}

export function applyProjectDoMigrations(
  storage: DurableObjectStorage,
  plan: ProjectDoMigrationPlan,
): void {
  const sql = storage.sql;
  const current = readProjectDoSchemaVersion(sql);
  const latest = plan.baseVersion + plan.steps.length;
  if (current > latest) {
    throw new Error(
      `project DO schema version ${current} is newer than this deployment supports ` +
        `(max ${latest}); refusing to run older code on a newer schema`,
    );
  }
  if (current > 0 && current < plan.baseVersion) {
    throw new Error(`project DO schema_meta.version is corrupt: ${current}`);
  }
  if (current === 0) {
    storage.transactionSync(() => {
      plan.base.apply(sql);
      sql.exec(
        `INSERT INTO schema_meta (id, version) VALUES (1, ?)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version`,
        plan.baseVersion,
      );
    });
  }
  for (const [index, step] of plan.steps.entries()) {
    const version = plan.baseVersion + index + 1;
    if (version <= current) {
      continue;
    }
    storage.transactionSync(() => {
      step.apply(sql);
      sql.exec(
        `INSERT INTO schema_meta (id, version) VALUES (1, ?)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version`,
        version,
      );
    });
  }
}

export function ensureProjectDoTables(storage: DurableObjectStorage): void {
  applyProjectDoMigrations(storage, PROJECT_DO_MIGRATIONS);
  ensureAuditWriteTrigger(storage.sql);
}
