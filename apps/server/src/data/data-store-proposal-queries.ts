// The sealed-proposal reads of the data store (AUTH_SPEC §14-5 —
// head / variables / wraps reads and the pending scans) — assembled
// into DataStoreShape by dataStoreLayer in data-store.ts.

import { Effect } from "effect";

import { numberColumn, stringColumn, type StoredRow } from "./data-store-rows.ts";
import type { StoredProposal, StoredProposalVariable } from "./data-store.ts";

/** The stored facts (a JSON array of strings written by insertProposal — anything else is storage corruption). */
function storedFacts(value: string): readonly string[] {
  const parsed: unknown = JSON.parse(value);
  if (!Array.isArray(parsed) || !parsed.every((fact) => typeof fact === "string")) {
    throw new Error("stored proposal facts are not a string array");
  }
  return parsed;
}

/**
 * Sealed value proposals (AUTH_SPEC §14-5). A proposal is read as three
 * queries (head / variables / wraps); the wraps are attached in variable
 * order. Only pending rows (expires_at > now) are returned by the
 * pending readers — expired rows wait for the sweep but never surface.
 */
export const makeProposalQueries = (sql: SqlStorage) => {
  const proposalOf = (row: StoredRow): StoredProposal => {
    const proposalId = stringColumn(row, "proposal_id");
    const wraps = sql
      .exec(
        `SELECT variable_id, recipient_user_id, recipient_enc_pub_hex, enc_hex, ciphertext_hex
         FROM rotation_proposal_wraps WHERE proposal_id = ?
         ORDER BY variable_id, recipient_user_id, recipient_enc_pub_hex`,
        proposalId,
      )
      .toArray();
    const variables = sql
      .exec(
        "SELECT variable_id, base_version FROM rotation_proposal_variables WHERE proposal_id = ? ORDER BY position",
        proposalId,
      )
      .toArray()
      .map((variable): StoredProposalVariable => {
        const variableId = stringColumn(variable, "variable_id");
        return {
          variableId,
          baseVersion: numberColumn(variable, "base_version"),
          wraps: wraps
            .filter((wrap) => stringColumn(wrap, "variable_id") === variableId)
            .map((wrap) => ({
              recipientUserId: stringColumn(wrap, "recipient_user_id"),
              recipientEncPubHex: stringColumn(wrap, "recipient_enc_pub_hex"),
              encHex: stringColumn(wrap, "enc_hex"),
              ciphertextHex: stringColumn(wrap, "ciphertext_hex"),
            })),
        };
      });
    return {
      proposalId,
      environmentId: stringColumn(row, "environment_id"),
      connector: stringColumn(row, "connector"),
      facts: storedFacts(stringColumn(row, "facts_json")),
      claimsDigestHex: stringColumn(row, "claims_digest_hex"),
      grantChainSeq: numberColumn(row, "grant_chain_seq"),
      createdAtMs: numberColumn(row, "created_at"),
      expiresAtMs: numberColumn(row, "expires_at"),
      variables,
    };
  };
  const HEAD_COLUMNS =
    "proposal_id, environment_id, connector, facts_json, claims_digest_hex, grant_chain_seq, created_at, expires_at";
  return {
    proposalExists: (proposalId: string) =>
      Effect.sync(
        () =>
          sql
            .exec("SELECT 1 AS present FROM rotation_proposals WHERE proposal_id = ?", proposalId)
            .toArray().length > 0,
      ),
    findProposal: (proposalId: string) =>
      Effect.sync(() => {
        const row = sql
          .exec(`SELECT ${HEAD_COLUMNS} FROM rotation_proposals WHERE proposal_id = ?`, proposalId)
          .toArray()[0];
        return row === undefined ? null : proposalOf(row);
      }),
    listPendingProposals: (nowMs: number) =>
      Effect.sync(() =>
        sql
          .exec(
            `SELECT ${HEAD_COLUMNS} FROM rotation_proposals WHERE expires_at > ? ORDER BY created_at, proposal_id`,
            nowMs,
          )
          .toArray()
          .map(proposalOf),
      ),
    countPendingProposals: (nowMs: number) =>
      Effect.sync(() =>
        numberColumn(
          sql
            .exec("SELECT COUNT(*) AS n FROM rotation_proposals WHERE expires_at > ?", nowMs)
            .toArray()[0] ?? { n: 0 },
          "n",
        ),
      ),
    variableHasPendingProposal: (environmentId: string, variableId: string, nowMs: number) =>
      Effect.sync(
        () =>
          sql
            .exec(
              `SELECT 1 AS present FROM rotation_proposals AS p
               JOIN rotation_proposal_variables AS v ON v.proposal_id = p.proposal_id
               WHERE p.environment_id = ? AND v.variable_id = ? AND p.expires_at > ? LIMIT 1`,
              environmentId,
              variableId,
              nowMs,
            )
            .toArray().length > 0,
      ),
  };
};
