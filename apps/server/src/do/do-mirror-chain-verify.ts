import {
  type ChainAnchors,
  checkpointRowsMatchLatest,
  epochAt,
  foldChainAnchors,
} from "./chain-anchors.ts";
import { verifyAuditAnchoredState } from "./do-mirror-audit-verify.ts";
import {
  CHECKPOINT_TABLE,
  columnsOf,
  ENVIRONMENTS_TABLE,
  hasTable,
  malformed,
  MANIFEST_TABLE,
  rowsByKey,
  rowsDiffer,
  stagedRowOf,
  stagingOf,
  VARIABLES_TABLE,
} from "./do-mirror-state.ts";
import { CHAIN_TABLE, readWatermarks } from "./do-snapshot.ts";

function stagedEnvCount(sql: SqlStorage, table: string, environmentId: string): number {
  const staging = stagingOf(table);
  if (!hasTable(sql, staging)) {
    return 0;
  }
  return Number(
    sql.exec(`SELECT COUNT(*) AS n FROM ${staging} WHERE environment_id = ?`, environmentId).one()[
      "n"
    ],
  );
}

export function verifyChainAnchoredProjections(sql: SqlStorage): void {
  if (!hasTable(sql, stagingOf(CHAIN_TABLE))) {
    return;
  }
  const anchors = foldChainAnchors(
    sql
      .exec(`SELECT seq, entry_json, entry_hash_hex FROM ${stagingOf(CHAIN_TABLE)} ORDER BY seq`)
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        entryJson: String(row["entry_json"]),
        entryHashHex: String(row["entry_hash_hex"]),
      })),
  );
  if (!anchors.complete) {
    return;
  }
  verifyStagedCheckpoints(sql, anchors);
  verifyStagedManifests(sql, anchors);
  verifyStagedTombstones(sql, anchors);
  verifyStagedWraps(sql, anchors);
  verifyStagedAttestations(sql, anchors);
  verifyAuditAnchoredState(sql, anchors);
}

function verifyStagedCheckpoints(sql: SqlStorage, anchors: ChainAnchors): void {
  const staging = stagingOf(CHECKPOINT_TABLE);
  const staged = hasTable(sql, staging) ? sql.exec(`SELECT * FROM ${staging}`).toArray() : [];
  if (!checkpointRowsMatchLatest(staged, anchors.latest)) {
    throw malformed();
  }
}

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the manifest binding's checks in the order the manifest's own fields are bound; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedManifests(sql: SqlStorage, anchors: ChainAnchors): void {
  const staging = stagingOf(MANIFEST_TABLE);
  const staged = hasTable(sql, staging) ? sql.exec(`SELECT * FROM ${staging}`).toArray() : [];
  const seen = new Set<string>();
  for (const row of staged) {
    const environmentId = String(row["environment_id"]);
    seen.add(environmentId);
    if (anchors.deletedSeq.has(environmentId)) {
      throw malformed();
    }
    const manifestVersion = Number(row["manifest_version"]);
    const epoch = Number(row["epoch"]);
    const chainHeadSeq = Number(row["chain_head_seq"]);
    if (anchors.hashBySeq.get(chainHeadSeq) !== String(row["chain_head_hash_hex"])) {
      throw malformed();
    }
    const tuple = anchors.tupleFor.get(`${environmentId}\n${manifestVersion}`);
    if (tuple === "conflict") {
      throw malformed();
    }
    if (tuple !== undefined) {
      if (tuple.epoch !== epoch || tuple.sig !== String(row["signed_bytes_hash_hex"])) {
        throw malformed();
      }
    } else if (epochAt(anchors, environmentId, chainHeadSeq) !== epoch) {
      throw malformed();
    }
    const baseline = anchors.latest.get(environmentId);
    if (
      baseline !== undefined &&
      (manifestVersion < baseline.manifestVersion || epoch < baseline.epoch)
    ) {
      throw malformed();
    }
    if (epochAt(anchors, environmentId, anchors.headSeq) !== epoch) {
      throw malformed();
    }
    const expectedVersion =
      stagedEnvCount(sql, "environment_meta_statements", environmentId) +
      stagedEnvCount(sql, "variable_meta_statements", environmentId) +
      (anchors.rotateCounts.get(environmentId) ?? 0);
    if (manifestVersion !== expectedVersion) {
      throw malformed();
    }
    const environment = stagedRowOf(sql, ENVIRONMENTS_TABLE, environmentId);
    const metaVersion =
      environment === undefined ? null : Number(environment["latest_meta_version"]);
    if (
      environment === undefined ||
      metaVersion !== Number(row["env_meta_version"]) ||
      !hasTable(sql, stagingOf("environment_meta_statements"))
    ) {
      throw malformed();
    }
    const statement = sql
      .exec(
        `SELECT signed_bytes_hash_hex FROM ${stagingOf("environment_meta_statements")} WHERE environment_id = ? AND meta_version = ?`,
        environmentId,
        metaVersion,
      )
      .toArray()[0];
    if (
      statement === undefined ||
      String(statement["signed_bytes_hash_hex"]) !== String(row["env_meta_sig_hash_hex"])
    ) {
      throw malformed();
    }
  }
  for (const environmentId of anchors.epochStarts.keys()) {
    if (anchors.deletedSeq.has(environmentId) || seen.has(environmentId)) {
      continue;
    }
    const environment = stagedRowOf(sql, ENVIRONMENTS_TABLE, environmentId);
    if (environment !== undefined && environment["deleted_at"] === null) {
      throw malformed();
    }
  }
}

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the tombstone exemptions in one pass over the staged rows; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedTombstones(sql: SqlStorage, anchors: ChainAnchors): void {
  const envStaging = stagingOf(ENVIRONMENTS_TABLE);
  if (hasTable(sql, envStaging)) {
    for (const row of sql.exec(`SELECT * FROM ${envStaging}`).toArray()) {
      const environmentId = String(row["environment_id"]);
      const deleted = row["deleted_at"] !== null;
      if (deleted !== anchors.deletedSeq.has(environmentId)) {
        throw malformed();
      }
    }
  }
  for (const environmentId of anchors.epochStarts.keys()) {
    if (stagedRowOf(sql, ENVIRONMENTS_TABLE, environmentId) === undefined) {
      throw malformed();
    }
  }
  const varStaging = stagingOf(VARIABLES_TABLE);
  const stmtStaging = stagingOf("variable_meta_statements");
  if (!hasTable(sql, varStaging) || !hasTable(sql, stmtStaging)) {
    return;
  }
  for (const row of sql
    .exec(`SELECT * FROM ${varStaging} WHERE deleted_at IS NOT NULL`)
    .toArray()) {
    const statement = sql
      .exec(
        `SELECT status FROM ${stmtStaging} WHERE environment_id = ? AND variable_id = ? AND meta_version = ?`,
        String(row["environment_id"]),
        String(row["variable_id"]),
        Number(row["latest_meta_version"]),
      )
      .toArray()[0];
    if (statement === undefined || String(statement["status"]) !== "deleted") {
      throw malformed();
    }
  }
}

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the wrap preservation and admission checks in one pass; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedWraps(sql: SqlStorage, anchors: ChainAnchors): void {
  const table = "dek_wraps";
  const keyColumns = ["environment_id", "epoch", "recipient_user_id", "recipient_enc_pub_hex"];
  const staged = rowsByKey(sql, table, true, keyColumns);
  for (const row of staged.values()) {
    const current = epochAt(anchors, String(row["environment_id"]), anchors.headSeq);
    const epoch = Number(row["epoch"]);
    if (current === undefined || !Number.isInteger(epoch) || epoch < 1 || epoch > current) {
      throw malformed();
    }
  }
  const liveHeadSeq = readWatermarks(sql).chainHeadSeq;
  const columns = columnsOf(sql, table);
  for (const [key, live] of rowsByKey(sql, table, false, keyColumns)) {
    const stagedRow = staged.get(key);
    if (stagedRow !== undefined) {
      if (rowsDiffer(columns, live, stagedRow)) {
        throw malformed();
      }
      continue;
    }
    if (anchors.deletedSeq.has(String(live["environment_id"]))) {
      continue;
    }
    const swept =
      String(live["recipient_class"]) === "member" &&
      anchors.addMemberSweeps.some(
        (sweep) =>
          sweep.seq > liveHeadSeq &&
          sweep.targetUserId === String(live["recipient_user_id"]) &&
          sweep.encPubHex !== String(live["recipient_enc_pub_hex"]),
      );
    if (!swept) {
      throw malformed();
    }
  }
}

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the attestation preservation and head-resolution checks in one pass; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedAttestations(sql: SqlStorage, anchors: ChainAnchors): void {
  const table = "head_attestations";
  const keyColumns = ["attester_user_id", "attester_key_fingerprint"];
  const staged = rowsByKey(sql, table, true, keyColumns);
  for (const row of staged.values()) {
    if (
      anchors.hashBySeq.get(Number(row["chain_head_seq"])) !== String(row["chain_head_hash_hex"])
    ) {
      throw malformed();
    }
  }
  const liveHeadSeq = readWatermarks(sql).chainHeadSeq;
  const columns = columnsOf(sql, table);
  for (const [key, live] of rowsByKey(sql, table, false, keyColumns)) {
    const stagedRow = staged.get(key);
    if (stagedRow === undefined) {
      const userId = String(live["attester_user_id"]);
      const removed = anchors.removedMembers.some(
        (removal) => removal.seq > liveHeadSeq && removal.targetUserId === userId,
      );
      const revoked = anchors.revokedDevices.some(
        (revocation) =>
          revocation.seq > liveHeadSeq &&
          revocation.targetUserId === userId &&
          revocation.fingerprints.includes(String(live["attester_key_fingerprint"])),
      );
      if (!removed && !revoked) {
        throw malformed();
      }
      continue;
    }
    if (Number(stagedRow["chain_head_seq"]) < Number(live["chain_head_seq"])) {
      throw malformed();
    }
    if (Number(stagedRow["chain_head_seq"]) === Number(live["chain_head_seq"])) {
      if (rowsDiffer(columns, live, stagedRow)) {
        throw malformed();
      }
    } else if (Number(stagedRow["accepted_at"]) < Number(live["accepted_at"])) {
      throw malformed();
    }
  }
}
