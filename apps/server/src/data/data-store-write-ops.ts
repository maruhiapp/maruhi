// The synchronous write functions of the data store (DataWriteOps —
// every write of one operation, audit appends included, bundled into
// one synchronous block) — assembled into the service's `write` by
// dataStoreLayer in data-store.ts.

import type { MetaStatementInput } from "./data-plane.ts";
import { numberColumn, stringColumn } from "./data-store-rows.ts";
import type { DataWriteOps, ExpiredProposal, MetaAuthorInfo } from "./data-store.ts";

/**
 * The layout-v2 column values (layout_version + the schema fields —
 * variable statements only). A v1 statement has layout_version 1 and
 * NULL schema fields. required is stored as the signed-target "true" /
 * "false" representation (identical to CRYPTO_SPEC §4.2's LP field).
 */
function layoutColumnValues(statement: MetaStatementInput): readonly (string | number | null)[] {
  const layoutVersion = statement.layoutVersion ?? 1;
  const schema = statement.schema;
  if (schema === undefined) {
    return [layoutVersion, null, null, null, null];
  }
  // max_age_days: NULL on a v2 row; the signed string ("" = none) on a v3 row
  const maxAge =
    schema.maxAgeDays === undefined
      ? null
      : schema.maxAgeDays === null
        ? ""
        : String(schema.maxAgeDays);
  return [
    layoutVersion,
    schema.varType,
    schema.required ? "true" : "false",
    schema.description,
    maxAge,
  ];
}

/**
 * The INSERT of a statement row (the column order shared by variable
 * and environment; only the table name is swapped). The variable side
 * also writes the layout-v2 columns ({@link layoutColumnValues}).
 */
function insertStatementRow(
  sql: SqlStorage,
  table: "variable_meta_statements" | "environment_meta_statements",
  keys: readonly (string | number)[],
  statement: MetaStatementInput,
  signedBytesHashHex: string,
  author: MetaAuthorInfo,
  nowMs: number,
): void {
  const isVariable = table === "variable_meta_statements";
  const keyColumns = isVariable
    ? "environment_id, variable_id, meta_version"
    : "environment_id, meta_version";
  const layoutColumns = isVariable
    ? ", layout_version, var_type, required, description, max_age_days"
    : "";
  const values: readonly (string | number | null)[] = [
    ...keys,
    statement.suite,
    statement.name,
    statement.status,
    statement.prevMetaSigHashHex,
    statement.chainHeadHashHex,
    statement.chainHeadSeq,
    statement.signatureHex,
    signedBytesHashHex,
    author.userId,
    author.keyFingerprintHex,
    nowMs,
    ...(isVariable ? layoutColumnValues(statement) : []),
  ];
  sql.exec(
    `INSERT INTO ${table}
       (${keyColumns}, suite, name, status, prev_meta_sig_hash_hex,
        chain_head_hash_hex, chain_head_seq, signature_hex, signed_bytes_hash_hex,
        author_user_id, author_key_fingerprint, created_at${layoutColumns})
     VALUES (${values.map(() => "?").join(", ")})`,
    ...values,
  );
}

export const makeWriteOps = (sql: SqlStorage): DataWriteOps => ({
  // latest_meta_version is inserted as 0 and settled by the
  // insertEnvironmentMetaStatement (metaVersion 1) inside the same
  // synchronous block
  insertEnvironment: (environmentId, name, nowMs) => {
    sql.exec(
      "INSERT INTO environments (environment_id, name, latest_meta_version, created_at, deleted_at) VALUES (?, ?, 0, ?, NULL)",
      environmentId,
      name,
      nowMs,
    );
  },
  insertEnvironmentMetaStatement: (environmentId, statement, signedBytesHashHex, author, nowMs) => {
    insertStatementRow(
      sql,
      "environment_meta_statements",
      [environmentId, statement.metaVersion],
      statement,
      signedBytesHashHex,
      author,
      nowMs,
    );
    sql.exec(
      "UPDATE environments SET name = ?, latest_meta_version = ? WHERE environment_id = ?",
      statement.name,
      statement.metaVersion,
      environmentId,
    );
  },
  retireEnvironment: (environmentId, nowMs) => {
    sql.exec(
      "UPDATE environments SET deleted_at = ? WHERE environment_id = ?",
      nowMs,
      environmentId,
    );
    sql.exec("DELETE FROM variables WHERE environment_id = ?", environmentId);
    // The subordinate variable statements are also deleted immediately
    // (the §12-4 subordinate data). The environment's own statement
    // chain (deleted included) stays in environment_meta_statements —
    // since an environment ID cannot be reused under the chain
    // consensus rules, nothing on the variable side remains as
    // detection material
    sql.exec("DELETE FROM variable_meta_statements WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM variable_versions WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM dek_wraps WHERE environment_id = ?", environmentId);
    // The environment manifest is also cascade-deleted (§12-4: a
    // deleted environment has no distribution channel, and a
    // server-stored artifact that is never distributed has no residual
    // value as detection material. The environment's own deleted
    // statement is the terminal detection material)
    sql.exec("DELETE FROM environment_manifests WHERE environment_id = ?", environmentId);
    // The checkpoint tuple and value snapshot are cascade-deleted by
    // the same argument (§12-4: a deleted environment's snapshot has no
    // distribution channel)

    sql.exec("DELETE FROM environment_checkpoints WHERE environment_id = ?", environmentId);
    sql.exec("DELETE FROM checkpoint_snapshot_values WHERE environment_id = ?", environmentId);
  },
  insertVariable: (environmentId, variableId, name, nowMs) => {
    sql.exec(
      `INSERT INTO variables (environment_id, variable_id, name, latest_meta_version, latest_version, created_at, deleted_at)
       VALUES (?, ?, ?, 0, 0, ?, NULL)`,
      environmentId,
      variableId,
      name,
      nowMs,
    );
  },
  insertVariableMetaStatement: (
    environmentId,
    variableId,
    statement,
    signedBytesHashHex,
    author,
    nowMs,
  ) => {
    insertStatementRow(
      sql,
      "variable_meta_statements",
      [environmentId, variableId, statement.metaVersion],
      statement,
      signedBytesHashHex,
      author,
      nowMs,
    );
    sql.exec(
      "UPDATE variables SET name = ?, latest_meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      statement.name,
      statement.metaVersion,
      environmentId,
      variableId,
    );
  },
  retireVariable: (environmentId, variableId, nowMs) => {
    sql.exec(
      "UPDATE variables SET deleted_at = ? WHERE environment_id = ? AND variable_id = ?",
      nowMs,
      environmentId,
      variableId,
    );
    sql.exec(
      "DELETE FROM variable_versions WHERE environment_id = ? AND variable_id = ?",
      environmentId,
      variableId,
    );
  },
  // Only the latest one is kept per environment (§12-5 — replaced via
  // upsert; rows are not accumulated)
  upsertEnvironmentManifest: (environmentId, manifest, signedBytesHashHex, issuer, nowMs) => {
    sql.exec(
      `INSERT INTO environment_manifests
         (environment_id, manifest_version, suite, epoch, variables_digest_hex,
          env_meta_version, env_meta_sig_hash_hex, prev_manifest_sig_hash_hex,
          chain_head_hash_hex, chain_head_seq, signature_hex, signed_bytes_hash_hex,
          issuer_user_id, issuer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (environment_id) DO UPDATE SET
         manifest_version = excluded.manifest_version,
         suite = excluded.suite,
         epoch = excluded.epoch,
         variables_digest_hex = excluded.variables_digest_hex,
         env_meta_version = excluded.env_meta_version,
         env_meta_sig_hash_hex = excluded.env_meta_sig_hash_hex,
         prev_manifest_sig_hash_hex = excluded.prev_manifest_sig_hash_hex,
         chain_head_hash_hex = excluded.chain_head_hash_hex,
         chain_head_seq = excluded.chain_head_seq,
         signature_hex = excluded.signature_hex,
         signed_bytes_hash_hex = excluded.signed_bytes_hash_hex,
         issuer_user_id = excluded.issuer_user_id,
         issuer_key_fingerprint = excluded.issuer_key_fingerprint,
         created_at = excluded.created_at`,
      environmentId,
      manifest.manifestVersion,
      manifest.suite,
      manifest.epoch,
      manifest.variablesDigestHex,
      manifest.envMetaVersion,
      manifest.envMetaSigHashHex,
      manifest.prevManifestSigHashHex,
      manifest.chainHeadHashHex,
      manifest.chainHeadSeq,
      manifest.signatureHex,
      signedBytesHashHex,
      issuer.userId,
      issuer.keyFingerprintHex,
      nowMs,
    );
  },
  upsertCheckpointSnapshot: (environmentId, checkpoint, values, nowMs) => {
    // The digest of the stored enumeration (read before overwriting).
    // Every call site has already cross-checked "the digest of values =
    // checkpoint.valuesDigestHex" before saving
    // (ensureCheckpointValuesDigest — the 3 paths: standalone / create
    // / rotate), both tables' rows are written only inside the same
    // synchronous block, and deletion happens to both tables together
    // (retireEnvironment). So a stored row's values_digest_hex is the
    // SHA-256 of the stored enumeration itself, and a match means the
    // enumeration is identical — skipping the wholesale replacement
    // leaves the stored state unchanged (keeping §6.4's "the state at
    // acceptance time itself"). The tuple-coordinates row is always
    // updated
    const stored = sql
      .exec(
        "SELECT values_digest_hex FROM environment_checkpoints WHERE environment_id = ?",
        environmentId,
      )
      .toArray()[0];
    const valuesUnchanged =
      stored !== undefined &&
      stringColumn(stored, "values_digest_hex") === checkpoint.valuesDigestHex;
    sql.exec(
      `INSERT INTO environment_checkpoints
         (environment_id, chain_seq, entry_hash_hex, epoch, manifest_version,
          manifest_sig_hash_hex, values_digest_hex, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (environment_id) DO UPDATE SET
         chain_seq = excluded.chain_seq,
         entry_hash_hex = excluded.entry_hash_hex,
         epoch = excluded.epoch,
         manifest_version = excluded.manifest_version,
         manifest_sig_hash_hex = excluded.manifest_sig_hash_hex,
         values_digest_hex = excluded.values_digest_hex,
         updated_at = excluded.updated_at`,
      environmentId,
      checkpoint.chainSeq,
      checkpoint.entryHashHex,
      checkpoint.epoch,
      checkpoint.manifestVersion,
      checkpoint.manifestSigHashHex,
      checkpoint.valuesDigestHex,
      nowMs,
    );
    if (valuesUnchanged) {
      return;
    }
    // The enumeration is a wholesale replacement per environment (the
    // state at acceptance time itself — the §6.4 upsert semantics)
    sql.exec("DELETE FROM checkpoint_snapshot_values WHERE environment_id = ?", environmentId);
    for (const value of values) {
      sql.exec(
        `INSERT INTO checkpoint_snapshot_values
           (environment_id, variable_id, version, value_sig_hash_hex)
         VALUES (?, ?, ?, ?)`,
        environmentId,
        value.variableId,
        value.version,
        value.valueSigHashHex,
      );
    }
  },
  insertVersion: (
    environmentId,
    variableId,
    value,
    ciphertextBytes,
    signedBytesHashHex,
    writer,
    nowMs,
  ) => {
    sql.exec(
      `INSERT INTO variable_versions
         (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes,
          prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex,
          signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      environmentId,
      variableId,
      value.version,
      value.suite,
      value.epoch,
      value.nonceHex,
      value.ciphertextHex,
      ciphertextBytes,
      value.prevValueSigHashHex,
      value.chainHeadHashHex,
      value.chainHeadSeq,
      value.signatureHex,
      signedBytesHashHex,
      writer.userId,
      writer.keyFingerprintHex,
      nowMs,
    );
    sql.exec(
      "UPDATE variables SET latest_version = ? WHERE environment_id = ? AND variable_id = ?",
      value.version,
      environmentId,
      variableId,
    );
  },
  insertWrap: (environmentId, wrap, signer, nowMs) => {
    sql.exec(
      `INSERT INTO dek_wraps
         (environment_id, epoch, recipient_class, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex, ciphertext_hex,
          signature_hex, signer_user_id, signer_key_fingerprint, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      environmentId,
      wrap.epoch,
      wrap.recipientClass,
      wrap.recipientUserId,
      wrap.suite,
      wrap.recipientEncPubHex,
      wrap.encHex,
      wrap.ciphertextHex,
      wrap.signatureHex,
      signer.userId,
      signer.keyFingerprintHex,
      nowMs,
    );
  },
  deleteWrap: (environmentId, epoch, recipientUserId, recipientEncPubHex) => {
    sql.exec(
      "DELETE FROM dek_wraps WHERE environment_id = ? AND epoch = ? AND recipient_user_id = ? AND recipient_enc_pub_hex = ?",
      environmentId,
      epoch,
      recipientUserId,
      recipientEncPubHex,
    );
  },
  // Two statements, SELECT → DELETE, but inside the same synchronous
  // task (under the permit, committed atomically). Since recipient is
  // the third component of the primary key, a key-prefix match is
  // impossible, so it is looked up via the recipient index dw_recipient
  // (recipient_user_id, recipient_class) (created by the do-schema.ts
  // base step) — the scan is limited to the wrap rows addressed to
  // the target user_id (test/do-schema.test.ts pins it via EXPLAIN
  // QUERY PLAN)
  deleteStaleMemberWraps: (recipientUserId, keepEncPubHex) => {
    const stale = sql
      .exec(
        `SELECT environment_id, epoch FROM dek_wraps
         WHERE recipient_user_id = ? AND recipient_class = 'member'
           AND recipient_enc_pub_hex != ?
         ORDER BY environment_id, epoch`,
        recipientUserId,
        keepEncPubHex,
      )
      .toArray()
      .map((row) => ({
        environmentId: stringColumn(row, "environment_id"),
        epoch: numberColumn(row, "epoch"),
      }));
    if (stale.length > 0) {
      sql.exec(
        `DELETE FROM dek_wraps
         WHERE recipient_user_id = ? AND recipient_class = 'member'
           AND recipient_enc_pub_hex != ?`,
        recipientUserId,
        keepEncPubHex,
      );
    }
    return stale;
  },
  upsertHeadAttestation: (attestation, nowMs) => {
    sql.exec(
      `INSERT INTO head_attestations
         (attester_user_id, suite, chain_head_seq, chain_head_hash_hex,
          signature_hex, attester_key_fingerprint, accepted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(attester_user_id, attester_key_fingerprint) DO UPDATE SET
         suite = excluded.suite,
         chain_head_seq = excluded.chain_head_seq,
         chain_head_hash_hex = excluded.chain_head_hash_hex,
         signature_hex = excluded.signature_hex,
         accepted_at = excluded.accepted_at`,
      attestation.attesterUserId,
      attestation.suite,
      attestation.chainHeadSeq,
      attestation.chainHeadHashHex,
      attestation.signatureHex,
      attestation.attesterKeyFingerprintHex,
      nowMs,
    );
  },
  deleteHeadAttestation: (attesterUserId) => {
    sql.exec("DELETE FROM head_attestations WHERE attester_user_id = ?", attesterUserId);
    sql.exec("DELETE FROM attestation_windows WHERE attester_user_id = ?", attesterUserId);
  },
  deleteDeviceHeadAttestation: (attesterUserId, keyFingerprintHex) => {
    sql.exec(
      "DELETE FROM head_attestations WHERE attester_user_id = ? AND attester_key_fingerprint = ?",
      attesterUserId,
      keyFingerprintHex,
    );
  },
  setSchemaPolicy: (policy) => {
    sql.exec(
      `INSERT INTO project_settings (id, schema_policy) VALUES (1, ?)
       ON CONFLICT (id) DO UPDATE SET schema_policy = excluded.schema_policy`,
      policy,
    );
  },
  insertProposal: (proposal, nowMs) => {
    sql.exec(
      `INSERT INTO rotation_proposals
         (proposal_id, environment_id, connector, facts_json, claims_digest_hex, grant_chain_seq, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      proposal.proposalId,
      proposal.environmentId,
      proposal.connector,
      JSON.stringify(proposal.facts),
      proposal.claimsDigestHex,
      proposal.grantChainSeq,
      nowMs,
      proposal.expiresAtMs,
    );
    // The minted order is the push order (companions first — CRYPTO_SPEC
    // §5.3); variable ids are random, so the position is stored
    proposal.variables.forEach((variable, position) => {
      sql.exec(
        "INSERT INTO rotation_proposal_variables (proposal_id, variable_id, base_version, position) VALUES (?, ?, ?, ?)",
        proposal.proposalId,
        variable.variableId,
        variable.baseVersion,
        position,
      );
      for (const wrap of variable.wraps) {
        sql.exec(
          `INSERT INTO rotation_proposal_wraps
             (proposal_id, variable_id, recipient_user_id, recipient_enc_pub_hex, enc_hex, ciphertext_hex)
           VALUES (?, ?, ?, ?, ?, ?)`,
          proposal.proposalId,
          variable.variableId,
          wrap.recipientUserId,
          wrap.recipientEncPubHex,
          wrap.encHex,
          wrap.ciphertextHex,
        );
      }
    });
  },
  deleteProposal: (proposalId) => {
    deleteProposalRows(sql, proposalId);
  },
  deleteExpiredProposals: (nowMs, except) => {
    const expired = sql
      .exec(
        "SELECT proposal_id, environment_id, expires_at FROM rotation_proposals WHERE expires_at <= ? AND proposal_id != ? ORDER BY expires_at, proposal_id",
        nowMs,
        except ?? "",
      )
      .toArray()
      .map((row): ExpiredProposal => ({
        proposalId: stringColumn(row, "proposal_id"),
        environmentId: stringColumn(row, "environment_id"),
        expiresAtMs: Number(row["expires_at"]),
      }));
    for (const { proposalId } of expired) {
      deleteProposalRows(sql, proposalId);
    }
    return expired;
  },
});

function deleteProposalRows(sql: SqlStorage, proposalId: string): void {
  sql.exec("DELETE FROM rotation_proposal_wraps WHERE proposal_id = ?", proposalId);
  sql.exec("DELETE FROM rotation_proposal_variables WHERE proposal_id = ?", proposalId);
  sql.exec("DELETE FROM rotation_proposals WHERE proposal_id = ?", proposalId);
}
