import type { EnvironmentId, VariableId } from "@maruhi/core";
import { Effect } from "effect";

import {
  environmentIdColumn,
  numberColumn,
  type StoredRow,
  stringColumn,
  userIdColumn,
  variableIdColumn,
} from "./data-store-rows.ts";
import type { StoredProposal, StoredProposalVariable } from "./data-store.ts";

function storedFacts(value: string): readonly string[] {
  const parsed: unknown = JSON.parse(value);
  if (!Array.isArray(parsed) || !parsed.every((fact) => typeof fact === "string")) {
    throw new Error("stored proposal facts are not a string array");
  }
  return parsed;
}

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
        const variableId = variableIdColumn(variable, "variable_id");
        return {
          variableId,
          baseVersion: numberColumn(variable, "base_version"),
          wraps: wraps
            .filter((wrap) => stringColumn(wrap, "variable_id") === variableId)
            .map((wrap) => ({
              recipientUserId: userIdColumn(wrap, "recipient_user_id"),
              recipientEncPubHex: stringColumn(wrap, "recipient_enc_pub_hex"),
              encHex: stringColumn(wrap, "enc_hex"),
              ciphertextHex: stringColumn(wrap, "ciphertext_hex"),
            })),
        };
      });
    return {
      proposalId,
      environmentId: environmentIdColumn(row, "environment_id"),
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
    variableHasPendingProposal: (
      environmentId: EnvironmentId,
      variableId: VariableId,
      nowMs: number,
    ) =>
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
