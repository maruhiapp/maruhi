// Table definitions and migration mechanism for the project DO (SQLite).
//
// - chain_entries: append-only storage of the membership chain (CRYPTO_SPEC §6.4)
// - environments / variables / variable_versions / dek_wraps: the data plane
//   (AUTH_SPEC §12). Deletion of environments / variables is represented by a
//   tombstone (deleted_at) and ID reuse is forbidden (§12-1). Ciphertexts and
//   wraps are deleted immediately
// - audit_events: the audit log (the AUDIT_SPEC §5.1 schema verbatim). seq is
//   monotonic with no gaps (numbering lives in audit-store.ts — the next seq
//   is held in DO memory)
// - schema_meta: the version of applied migrations (one row). Later schema
//   changes to existing DOs are appended to PROJECT_DO_MIGRATIONS as ordered
//   steps (re-applying CREATE cannot add columns to an existing table)
//
// Drizzle (drizzle-orm/durable-sqlite) is again deferred (continuing the
// session 05 decision; the ruling is in docs/notes/session-07.md): the queries
// are simple key lookups only, and plain SQL is kept inside the Store service
// boundary without adding a dependency. The D1 side (db.package) keeps using
// Drizzle.

// The current schema (all steps folded into one on 2026-09-26 — design record
// dk-design.md §22-4. The pre-fold DOs were recreated with each operator deploy).
const PROJECT_DO_DDL = [
  `CREATE TABLE chain_entries (
     seq INTEGER PRIMARY KEY,
     entry_json TEXT NOT NULL,
     entry_hash_hex TEXT NOT NULL,
     canonical_bytes INTEGER NOT NULL
   )`,
  // name / latest_meta_version are derived caches of the latest statement
  // (*_meta_statements) — used for the name-uniqueness query and the
  // metaVersion CAS. The statement rows are the source of truth and are kept in
  // sync during the write phase
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
  // Metadata statements (CRYPTO_SPEC §4.2 / AUTH_SPEC §12-5): for each
  // metaVersion, stores the signed_bytes hash (server-recomputed — verification
  // material for the prev check and 409 retries; not distributed), the
  // signature, the author (user_id + the chain-derived key FP at acceptance
  // time), name, status, prev, and the declared head.
  // Delete statements (status deleted) also keep being stored and distributed
  // (§12-4/-5 — detection material for denial of a deletion and for
  // unauthorized revival).
  // layout_version: the wire layout (the anchor for the layout-monotonicity
  // check of the next statement). var_type / required / description: the v2
  // schema fields (NULL on v1 rows. required is stored as the signed "true" /
  // "false" string representation)
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
  // The suite column: every persistent data structure carries a suite
  // identifier (CRYPTO_SPEC §2 design principle 4 / AUTH_SPEC §12-2 — lets a
  // future algorithm migration discriminate row by row)
  //
  // The value write-signature columns (CRYPTO_SPEC §4.1 / AUTH_SPEC §12-5):
  // prev_value_sig_hash_hex (empty string for version 1) / the declared head
  // (hash + seq) / the signature / the server-recomputed signed_bytes hash
  // (verification material for the prev check and 409 retries — not
  // distributed) / the writer at acceptance time (user_id + chain-derived key
  // FP). The signed-bytes body and public keys are not stored (reconstructible
  // from the coordinates and the chain)
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
  // DEK wraps (AUTH_SPEC §12-6). A slot = (environment, epoch, recipient,
  // recipient's device enc public key) — one slot per device of the same person
  // (the device expansion of R(E) — CRYPTO_SPEC §6.2).
  // signature_hex / signer_*: the registration signature (CRYPTO_SPEC §5.1) and
  // the signer.
  // For a recipient_class = server row, recipient_user_id holds the server key
  // FP (32 lowercase hex characters) — the column name stays user_id for
  // historical reasons. Cross-class collision with a member's user_id is guarded
  // by the acceptance stage (wrapStorageKey in dek-wraps.ts = 422; appending to
  // an existing epoch is a class-agnostic stored-existence check = 409 — A-1)
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
  // Recipient index: the §12-6 cleanup at re-add acceptance
  // (deleteStaleMemberWraps in data-store.ts) queries by
  // `recipient_user_id = ? AND recipient_class = 'member'` (the third primary-key
  // component cannot use a prefix match)
  `CREATE INDEX dw_recipient ON dek_wraps (recipient_user_id, recipient_class)`,
  // The AUDIT_SPEC §5.1 schema. row_id is the wire row identifier (16-byte
  // random hex — §7 ruling C1: the gapless seq never leaves the wire) and is
  // always generated by the append path (audit-store.ts)
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
  // The target / key-FP indexes are partial indexes (audit-log growth-density
  // measure 1): the dominant row kind `var.read` always has NULL in these
  // columns, so NULL rows stay out of the index. Every reader uses equality
  // conditions (equality implies IS NOT NULL), so the index is picked
  // (test/audit-index.test.ts pins it via EXPLAIN QUERY PLAN)
  `CREATE INDEX ae_target ON audit_events (target_user_id, seq) WHERE target_user_id IS NOT NULL`,
  `CREATE INDEX ae_target_fp ON audit_events (target_key_fingerprint, seq) WHERE target_key_fingerprint IS NOT NULL`,
  `CREATE INDEX ae_actor_fp ON audit_events (actor_key_fingerprint, seq) WHERE actor_key_fingerprint IS NOT NULL`,
  // Fixed-window counters for workload leases (AUTH_SPEC §14-3 / AUDIT_SPEC
  // §3.5). `kind` has only two rows: "issued" (the issuance window) / "denied"
  // (the denial-record window). A window is the best-effort "start time +
  // count" scheme (same shape as the §13-3 precedent). Window state needs
  // overwriting updates, so it cannot live in the (append-only) audit log
  `CREATE TABLE lease_windows (
     kind TEXT PRIMARY KEY,
     window_start INTEGER NOT NULL,
     count INTEGER NOT NULL
   )`,
  // First-come bindings for workload leases (the AUTH_SPEC §14-1 ruling —
  // docs/notes/session-24.md). At issuance it records "binding key → ephemeral
  // public key" and rejects a re-request with the same key + a different key.
  // `binding_key_hex` is the **SHA-256 of the JWS signing input
  // (`header.payload`)**, not a hash of the raw token (the raw token's
  // signature segment is malleable — see the doc of signingInputHashHex in
  // verifier.ts). `expires_at` is "the last time time-validation could accept
  // the token + a margin" (LEASE_BINDING_RETENTION_MARGIN_MS in policy.ts), and
  // the row count is bounded by the issuance rate window and GC (data-store.ts
  // — deletes expired rows when recording). Neither the token body nor claims
  // are stored (hash and public key only — both non-secret)
  `CREATE TABLE lease_bindings (
     binding_key_hex TEXT PRIMARY KEY,
     ephemeral_pub_hex TEXT NOT NULL,
     expires_at INTEGER NOT NULL
   )`,
  // Environment manifests (CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5). **Only the
  // latest manifest per environment is kept** (upsert with PRIMARY KEY =
  // environment_id). signed_bytes_hash_hex is server-recomputed (prev-matching
  // material for the next manifestVersion; not distributed). issuer is the
  // chain-derived member at acceptance time (user_id + key FP). A cascade
  // target of environment deletion (§12-4 — retireEnvironment deletes the row)
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
  // Checkpoint value snapshots (CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2). The tuple
  // of each environment's **latest covering checkpoint** (upsert), plus the
  // enumeration of value snapshots at that point (a full replacement per
  // environment). Existing snapshots of environments not included in the
  // payload are left unchanged (§6.4). Cascade targets of environment deletion
  // (retireEnvironment deletes both tables)
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
  // Computed columns of the audit head's cumulative hash (AUDIT_SPEC §5.1). A
  // deterministic derivation of audit_events (the append-only rows are the
  // source of truth); materialization is lazy extension (ensureHeadCurrent in
  // audit-store.ts — extends to MAX(seq) before audit-head reads and checkpoint
  // acceptance). Prefix-contiguous (a complete prefix of seq 1..k) as the
  // invariant; rows are never rewritten or deleted. The head_hash_hex index
  // serves the membership/position check of checkpoint acceptance (CRYPTO_SPEC
  // §6.4)
  `CREATE TABLE audit_head_hashes (
     seq INTEGER PRIMARY KEY,
     head_hash_hex TEXT NOT NULL
   )`,
  `CREATE INDEX ahh_hash ON audit_head_hashes (head_hash_hex)`,
  // Head attestations (CRYPTO_SPEC §6.6 / AUTH_SPEC §16-1). **One latest row
  // per device** (upsert with PK = (attester_user_id, attester_key_fingerprint)
  // — mutable data that never goes on the chain). Devices sync independently,
  // so no seq monotonicity across devices is required. accepted_at is stored
  // but **not distributed**. The row is deleted on `remove_member` acceptance
  // (an acceptance side effect in chain-accept.ts). attestation_windows is a
  // per-member fixed-window counter (60 per hour — §16-1; deleted together with
  // the attestation row on remove)
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
  // Project settings (one row). No row = schemaPolicy 'disabled' (the default
  // — AUTH_SPEC §12-11). Audited via project.schema_policy_changed (AUDIT_SPEC
  // §3.3)
  `CREATE TABLE project_settings (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     schema_policy TEXT NOT NULL
   )`,
];

/**
 * A single ordered migration step for the project DO's SQLite schema.
 *
 * `tables` lists the tables this step introduces — the test reset helper
 * derives its DELETE targets from these, so declare every new table here.
 */
export interface ProjectDoMigration {
  readonly tables: readonly string[];
  readonly apply: (sql: SqlStorage) => void;
}

// Ordered migration steps. **Appending at the end is the only allowed
// change** (editing, reordering, or deleting an applied step is forbidden
// because it would disagree with DOs already deployed externally). Each step
// may assume "a DB with all previous steps applied" (ALTER TABLE etc.).
// Each step applies "the body + the version bump" in one transaction
// (transactionSync), so an exception mid-step rolls the whole step back and the
// next constructor run retries from the start of the failed step (no partially
// applied DDL remains, so a step itself does not need to be written
// idempotently).
export const PROJECT_DO_MIGRATIONS: readonly ProjectDoMigration[] = [
  {
    tables: [
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
    ],
    apply(sql) {
      for (const statement of PROJECT_DO_DDL) {
        sql.exec(statement);
      }
    },
  },
  // Step 2 (2026-10-02 — PF6 R9 expiring values, CRYPTO_SPEC §4.2 layout
  // v3): the max_age_days column of variable statements. NULL on v1 / v2
  // rows; on a v3 row the signed string ("" = no declaration, else the
  // decimal day count)
  {
    tables: [],
    apply(sql) {
      sql.exec("ALTER TABLE variable_meta_statements ADD COLUMN max_age_days TEXT");
    },
  },
  // Step 3 (2026-10-02 — PF7b sealed value proposals, CRYPTO_SPEC §5.3 /
  // AUTH_SPEC §14-5): a proposal minted by a leased workload, its
  // variables (the version each replaces) and its sealed values (one row
  // per recipient device). Rows are deleted on resolution and on expiry
  // (the audit log keeps the history — rotation.proposed /
  // rotation.proposal_accepted / rotation.proposal_rejected). facts_json
  // is the connector's non-secret facts as a JSON array of strings;
  // nothing in these tables is decryptable by the server
  {
    tables: ["rotation_proposals", "rotation_proposal_variables", "rotation_proposal_wraps"],
    apply(sql) {
      sql.exec(`CREATE TABLE rotation_proposals (
         proposal_id TEXT PRIMARY KEY,
         environment_id TEXT NOT NULL,
         connector TEXT NOT NULL,
         facts_json TEXT NOT NULL,
         claims_digest_hex TEXT NOT NULL,
         grant_chain_seq INTEGER NOT NULL,
         created_at INTEGER NOT NULL,
         expires_at INTEGER NOT NULL
       )`);
      sql.exec(`CREATE TABLE rotation_proposal_variables (
         proposal_id TEXT NOT NULL,
         variable_id TEXT NOT NULL,
         base_version INTEGER NOT NULL,
         position INTEGER NOT NULL,
         PRIMARY KEY (proposal_id, variable_id)
       )`);
      sql.exec(`CREATE TABLE rotation_proposal_wraps (
         proposal_id TEXT NOT NULL,
         variable_id TEXT NOT NULL,
         recipient_user_id TEXT NOT NULL,
         recipient_enc_pub_hex TEXT NOT NULL,
         enc_hex TEXT NOT NULL,
         ciphertext_hex TEXT NOT NULL,
         PRIMARY KEY (proposal_id, variable_id, recipient_user_id, recipient_enc_pub_hex)
       )`);
    },
  },
];

/**
 * All project-DO table names, derived from the migration steps. The test
 * reset helper (test/support/project-do.ts) uses this as its DELETE list.
 * `schema_meta` is intentionally excluded: the applied-version row must
 * survive test resets so migrations are not re-applied to a populated schema.
 */
export const PROJECT_DO_TABLES: readonly string[] = PROJECT_DO_MIGRATIONS.flatMap(
  (migration) => migration.tables,
);

// version = "number of applied steps" (0 = none applied, PROJECT_DO_MIGRATIONS.length = latest)
const SCHEMA_META_DDL = `CREATE TABLE IF NOT EXISTS schema_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
)`;

/** Read the number of applied migration steps (0 for a fresh database). */
export function readProjectDoSchemaVersion(sql: SqlStorage): number {
  sql.exec(SCHEMA_META_DDL);
  const rows = sql.exec("SELECT version FROM schema_meta WHERE id = 1").toArray();
  const row = rows[0];
  if (row === undefined) {
    return 0;
  }
  const version = Number(row.version);
  if (!Number.isInteger(version) || version < 0) {
    // Treating a corrupt value as 0 would re-run every step (step 2 onward is
    // not idempotent), so fail explicitly and hand it to human investigation
    throw new Error(`project DO schema_meta.version is corrupt: ${String(row.version)}`);
  }
  return version;
}

/**
 * Apply the not-yet-applied migration steps in order. Each step and its
 * version bump run in one synchronous transaction, so a failing step rolls
 * back entirely and is retried from its start on the next call. Applied steps
 * are skipped, so calling this on an up-to-date database is a no-op.
 *
 * Refuses to run when the stored version is newer than this deployment's step
 * count: after a rollback deploy the old code cannot know the newer schema's
 * shape, and continuing silently risks writing through stale assumptions.
 */
export function applyProjectDoMigrations(
  storage: DurableObjectStorage,
  migrations: readonly ProjectDoMigration[],
): void {
  const sql = storage.sql;
  const current = readProjectDoSchemaVersion(sql);
  if (current > migrations.length) {
    // In the self-hosted distribution a rollback deploy to an older version
    // really happens. Do not silently run old code on a newer-schema DB
    // (operations rule: forward only). Mind the blast radius: this throw fires
    // in the DO constructor, so during a rollback no DO of an applied project
    // can open at all (an intentional consistency > availability choice;
    // recovery is a forward deploy). Assume this blast radius when adding a
    // step
    throw new Error(
      `project DO schema version ${current} is newer than this deployment supports ` +
        `(max ${migrations.length}); refusing to run older code on a newer schema`,
    );
  }
  for (const [index, migration] of migrations.entries()) {
    if (index < current) {
      continue;
    }
    storage.transactionSync(() => {
      migration.apply(sql);
      sql.exec(
        `INSERT INTO schema_meta (id, version) VALUES (1, ?)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version`,
        index + 1,
      );
    });
  }
}

/** Called from the DO constructor (idempotent). Applies only the not-yet-applied steps in order. */
export function ensureProjectDoTables(storage: DurableObjectStorage): void {
  applyProjectDoMigrations(storage, PROJECT_DO_MIGRATIONS);
}
