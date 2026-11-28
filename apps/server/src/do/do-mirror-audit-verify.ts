import { Effect } from "effect";

import { deriveAuditHeads, isAuditHeadHex } from "../audit-store.ts";
import { asRecord, type ChainAnchors, intField, strField } from "./chain-anchors.ts";
import {
  AUDIT_HEAD_TABLE,
  AUDIT_TABLE,
  columnsOf,
  hasTable,
  malformed,
  type MirrorPageRefusedError,
  type MirrorState,
  rowsByKey,
  rowsDiffer,
  stagedMaxSeq,
  stagingOf,
} from "./do-mirror-state.ts";

interface StagedProposalMint {
  readonly environmentId: string | null;
  readonly claimsDigestHex: string | null;
  readonly grantChainSeq: number | null;
  readonly connector: string | null;
  readonly variableIds: readonly string[];
  readonly open: boolean;
}

interface StagedAuditAnchors {
  readonly policy: string;
  readonly proposals: ReadonlyMap<string, StagedProposalMint>;
  readonly closed: ReadonlySet<string>;
}

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- a per-kind fold over the staged audit log's row kinds; the branches are the row kinds the settings and proposal bindings read
function stagedAuditAnchors(sql: SqlStorage): StagedAuditAnchors | null {
  const staging = stagingOf(AUDIT_TABLE);
  if (!hasTable(sql, staging)) {
    return null;
  }
  let policy = "enabled";
  const proposals = new Map<string, StagedProposalMint>();
  const closed = new Set<string>();
  const rows = sql
    .exec(
      `SELECT event, environment_id, payload FROM ${staging} WHERE event IN ('project.schema_policy_changed', 'rotation.proposed', 'rotation.proposal_accepted', 'rotation.proposal_rejected', 'rotation.proposal_expired', 'rotation.proposal_cancelled') ORDER BY seq`,
    )
    .toArray();
  for (const row of rows) {
    const event = String(row["event"]);
    const payload =
      typeof row["payload"] === "string" ? asRecord(safeParseJson(row["payload"])) : null;
    if (event === "project.schema_policy_changed") {
      const next = payload === null ? null : strField(payload, "next");
      if (
        payload === null ||
        strField(payload, "previous") !== policy ||
        (next !== "enabled" && next !== "locked")
      ) {
        throw malformed();
      }
      policy = next;
      continue;
    }
    const proposalId = payload === null ? null : strField(payload, "proposalId");
    if (payload === null || proposalId === null) {
      continue;
    }
    if (event === "rotation.proposed") {
      const rawIds = payload["variableIds"];
      proposals.set(proposalId, {
        environmentId: row["environment_id"] === null ? null : String(row["environment_id"]),
        claimsDigestHex: strField(payload, "claimsDigest"),
        grantChainSeq: intField(payload, "grantChainSeq"),
        connector: strField(payload, "connector"),
        variableIds: Array.isArray(rawIds)
          ? rawIds.filter((value): value is string => typeof value === "string")
          : [],
        open: true,
      });
      closed.delete(proposalId);
    } else {
      const mint = proposals.get(proposalId);
      if (mint !== undefined) {
        proposals.set(proposalId, { ...mint, open: false });
      }
      closed.add(proposalId);
    }
  }
  return { policy, proposals, closed };
}

function safeParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function verifyAuditAnchoredState(sql: SqlStorage, anchors: ChainAnchors): void {
  const audit = stagedAuditAnchors(sql);
  verifyStagedSettings(sql, audit);
  verifyStagedProposals(sql, anchors, audit);
}

function verifyStagedSettings(sql: SqlStorage, audit: StagedAuditAnchors | null): void {
  const table = "project_settings";
  const liveRow = sql.exec(`SELECT * FROM ${table} WHERE id = 1`).toArray()[0];
  if (!hasTable(sql, stagingOf(table))) {
    if (liveRow !== undefined) {
      throw malformed();
    }
    return;
  }
  const stagedRow = sql.exec(`SELECT * FROM ${stagingOf(table)} WHERE id = 1`).toArray()[0];
  const stagedPolicy = stagedRow === undefined ? "enabled" : String(stagedRow["schema_policy"]);
  const expected =
    audit === null
      ? liveRow === undefined
        ? "enabled"
        : String(liveRow["schema_policy"])
      : audit.policy;
  if (stagedPolicy !== expected) {
    throw malformed();
  }
}

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- the proposal binding and preservation checks in one pass; each branch is one refusal condition, and splitting the checklist would obscure it
function verifyStagedProposals(
  sql: SqlStorage,
  anchors: ChainAnchors,
  audit: StagedAuditAnchors | null,
): void {
  const proposalKey = ["proposal_id"] as const;
  const variableKey = ["proposal_id", "variable_id"] as const;
  const wrapKey = [
    "proposal_id",
    "variable_id",
    "recipient_user_id",
    "recipient_enc_pub_hex",
  ] as const;
  const liveProposals = rowsByKey(sql, "rotation_proposals", false, proposalKey);
  const stagedProposals = rowsByKey(sql, "rotation_proposals", true, proposalKey);
  const liveVariables = rowsByKey(sql, "rotation_proposal_variables", false, variableKey);
  const stagedVariables = rowsByKey(sql, "rotation_proposal_variables", true, variableKey);
  const liveWraps = rowsByKey(sql, "rotation_proposal_wraps", false, wrapKey);
  const stagedWraps = rowsByKey(sql, "rotation_proposal_wraps", true, wrapKey);
  const bound = new Set<string>();
  for (const [proposalId, row] of stagedProposals) {
    if (audit === null) {
      if (liveProposals.has(proposalId)) {
        bound.add(proposalId);
      }
      continue;
    }
    const mint = audit.proposals.get(proposalId);
    if (
      mint === undefined ||
      !mint.open ||
      mint.claimsDigestHex !== String(row["claims_digest_hex"]) ||
      mint.grantChainSeq !== Number(row["grant_chain_seq"]) ||
      mint.connector !== String(row["connector"]) ||
      (mint.environmentId !== null && mint.environmentId !== String(row["environment_id"]))
    ) {
      throw malformed();
    }
    const stagedIds = [...stagedVariables.keys()]
      .filter((key) => key.startsWith(`${proposalId}\n`))
      .map((key) => key.slice(proposalId.length + 1))
      .sort();
    if (JSON.stringify(stagedIds) !== JSON.stringify([...mint.variableIds].sort())) {
      throw malformed();
    }
    bound.add(proposalId);
  }
  for (const key of [...stagedVariables.keys(), ...stagedWraps.keys()]) {
    if (!bound.has(key.split("\n")[0] ?? "")) {
      throw malformed();
    }
  }
  const excused = (live: Record<string, unknown>): boolean => {
    const proposalId = String(live["proposal_id"]);
    if (audit !== null && audit.closed.has(proposalId)) {
      return true;
    }
    const parent = liveProposals.get(proposalId);
    return parent !== undefined && anchors.deletedSeq.has(String(parent["environment_id"]));
  };
  // fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
  // fallow-ignore-next-line complexity -- the proposal tables' preservation pass in both directions (a live row survives identically or is excused; a staged row is admitted only under a mint-bound proposal); each branch is one refusal condition
  const preserved = (
    table: string,
    liveRows: ReadonlyMap<string, Record<string, unknown>>,
    stagedRows: ReadonlyMap<string, Record<string, unknown>>,
    boundAdmitsExtra: boolean,
  ): void => {
    const columns = columnsOf(sql, table);
    for (const [key, live] of liveRows) {
      const stagedRow = stagedRows.get(key);
      if (stagedRow !== undefined) {
        if (rowsDiffer(columns, live, stagedRow)) {
          throw malformed();
        }
      } else if (!excused(live)) {
        throw malformed();
      }
    }
    for (const key of stagedRows.keys()) {
      if (!liveRows.has(key) && !(boundAdmitsExtra && bound.has(key.split("\n")[0] ?? ""))) {
        throw malformed();
      }
    }
  };
  preserved("rotation_proposals", liveProposals, stagedProposals, true);
  preserved("rotation_proposal_variables", liveVariables, stagedVariables, audit !== null);
  preserved("rotation_proposal_wraps", liveWraps, stagedWraps, audit !== null);
}

function stagedAuditHeadStart(
  sql: SqlStorage,
  state: MirrorState,
  stagedHeads: string,
): { readonly from: number; readonly start: string | null } {
  const firstReplica = state.lastAuditSeq === 0;
  const from = firstReplica ? stagedMaxSeq(sql, AUDIT_HEAD_TABLE) : state.lastAuditSeq;
  const table = firstReplica ? stagedHeads : AUDIT_HEAD_TABLE;
  const head =
    from === 0
      ? ""
      : sql.exec(`SELECT head_hash_hex FROM ${table} WHERE seq = ?`, from).toArray()[0]?.[
          "head_hash_hex"
        ];
  return { from, start: head === undefined ? null : String(head) };
}

export const verifyStagedAuditHeads = Effect.fn("do-mirror.verifyStagedAuditHeads")(function* (
  sql: SqlStorage,
  state: MirrorState,
): Effect.fn.Return<void, MirrorPageRefusedError> {
  const stagedHeads = stagingOf(AUDIT_HEAD_TABLE);
  const stagedLog = stagingOf(AUDIT_TABLE);
  if (!hasTable(sql, stagedLog)) {
    return;
  }
  if (!hasTable(sql, stagedHeads)) {
    sql.exec(
      `CREATE TABLE ${stagedHeads} AS SELECT seq, head_hash_hex FROM ${AUDIT_HEAD_TABLE} LIMIT 0`,
    );
    sql.exec(`CREATE INDEX ${stagedHeads}_seq ON ${stagedHeads} (seq)`);
  }
  const { from, start } = stagedAuditHeadStart(sql, state, stagedHeads);
  if (from !== 0 && !isAuditHeadHex(start)) {
    return yield* malformed();
  }
  sql.exec(`DELETE FROM ${stagedHeads} WHERE seq > ?`, from);
  const derived = yield* Effect.promise(() =>
    deriveAuditHeads(sql, stagedLog, stagedHeads, from, from === 0 ? "" : String(start)),
  );
  if (derived === null) {
    return yield* malformed();
  }
});
