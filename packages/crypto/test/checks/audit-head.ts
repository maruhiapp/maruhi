// AUDIT_SPEC §5.1 監査ヘッド累積ハッシュのチェック(PR-M2 — 2026-08-28
// セッション 35):
// - audit-head.json の chain セクション(row_digest と h_n の連鎖)を
//   computeAuditRowDigest / computeAuditHeadHash が再現する
// - NULL と空文字列のプリイメージ相違(null_vs_empty セクション)
// - 数値境界(非整数・2^53 以上)と hex 形式の invalid-input(規約 21 の分担 —
//   拒否は JSON ベクターでなくハーネス側で固定する)

import auditHeadVectors from "../../test-vectors/audit-head.json" with { type: "json" };

import type { AuditHeadRow } from "../../src/index.ts";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "../../src/index.ts";
import { type CheckResult, Checks } from "./support.ts";

/** ベクター JSON の行(推論リテラル型でなく構造型で受ける — chain と null_vs_empty の両方から渡す)。 */
interface VectorRow {
  readonly seq: number;
  readonly row_id: string | null;
  readonly server_ts: number;
  readonly client_ts: number | null;
  readonly event: string;
  readonly actor_type: string;
  readonly actor_user_id: string | null;
  readonly actor_key_fingerprint: string | null;
  readonly actor_api_token_id: string | null;
  readonly target_user_id: string | null;
  readonly target_key_fingerprint: string | null;
  readonly environment_id: string | null;
  readonly variable_id: string | null;
  readonly epoch: number | null;
  readonly version: number | null;
  readonly chain_seq: number | null;
  readonly payload: string | null;
}

function toTypedRow(row: VectorRow): AuditHeadRow {
  return {
    seq: row.seq,
    rowId: row.row_id,
    serverTs: row.server_ts,
    clientTs: row.client_ts,
    event: row.event,
    actorType: row.actor_type,
    actorUserId: row.actor_user_id,
    actorKeyFingerprintHex: row.actor_key_fingerprint,
    actorApiTokenId: row.actor_api_token_id,
    targetUserId: row.target_user_id,
    targetKeyFingerprintHex: row.target_key_fingerprint,
    environmentId: row.environment_id,
    variableId: row.variable_id,
    epoch: row.epoch,
    version: row.version,
    chainSeq: row.chain_seq,
    payloadText: row.payload,
  };
}

async function digestOf(row: VectorRow): Promise<string> {
  const digest = await computeAuditRowDigest(toTypedRow(row));
  if (!digest.ok) {
    throw new Error(`audit row digest failed: ${JSON.stringify(digest.error)}`);
  }
  return digest.value;
}

async function chainVectorChecks(c: Checks): Promise<void> {
  c.push(
    "audit-head: vector domain embeds suite",
    auditHeadVectors.domain === `${SUITE_ID}/audit-head`,
  );
  let head = auditHeadVectors.initial_head;
  for (const step of auditHeadVectors.chain) {
    const digest = await digestOf(step.row);
    c.push(
      `audit-head: seq ${step.row.seq} row digest`,
      digest === step.expected_row_digest_hex,
    );
    const next = await computeAuditHeadHash(SUITE_ID, head, step.row.seq, digest);
    c.push(
      `audit-head: seq ${step.row.seq} head hash`,
      next.ok && next.value === step.expected_head_hash_hex,
      next.ok ? undefined : JSON.stringify(next.error),
    );
    head = next.ok ? next.value : head;
  }
}

async function nullVsEmptyChecks(c: Checks): Promise<void> {
  const pair = auditHeadVectors.null_vs_empty;
  const nullDigest = await digestOf(pair.null_row);
  const emptyDigest = await digestOf(pair.empty_row);
  c.push("audit-head: null row digest", nullDigest === pair.null_row_digest_hex);
  c.push("audit-head: empty-string row digest", emptyDigest === pair.empty_row_digest_hex);
  c.push("audit-head: null and empty string differ", nullDigest !== emptyDigest);
}

/** 数値境界・hex 形式の invalid-input(拒否側の固定 — ベクター規約 21 の分担)。 */
async function invalidInputChecks(c: Checks): Promise<void> {
  const base = toTypedRow(auditHeadVectors.chain[0]!.row);
  const rejectsRow = async (name: string, row: AuditHeadRow, field: string): Promise<void> => {
    const digest = await computeAuditRowDigest(row);
    c.push(
      `audit-head invalid-input: ${name}`,
      !digest.ok && digest.error.kind === "InvalidInput" && digest.error.field === field,
      digest.ok ? "unexpectedly accepted" : JSON.stringify(digest.error),
    );
  };
  await rejectsRow("fractional seq", { ...base, seq: 1.5 }, "seq");
  await rejectsRow("zero seq", { ...base, seq: 0 }, "seq");
  await rejectsRow(
    "unsafe integer serverTs",
    { ...base, serverTs: Number.MAX_SAFE_INTEGER + 1 },
    "serverTs",
  );
  await rejectsRow("fractional epoch", { ...base, epoch: 2.5 }, "epoch");
  await rejectsRow(
    "unsafe integer version",
    { ...base, version: Number.MAX_SAFE_INTEGER + 1 },
    "version",
  );
  await rejectsRow("negative chainSeq", { ...base, chainSeq: -1 }, "chainSeq");

  const digest = await digestOf(auditHeadVectors.chain[0]!.row);
  const rejectsHead = async (
    name: string,
    args: readonly [string, string, number, string],
    field: string,
  ): Promise<void> => {
    const head = await computeAuditHeadHash(...args);
    c.push(
      `audit-head invalid-input: ${name}`,
      !head.ok && head.error.kind === "InvalidInput" && head.error.field === field,
      head.ok ? "unexpectedly accepted" : JSON.stringify(head.error),
    );
  };
  await rejectsHead("empty suite", ["", "", 1, digest], "suite");
  await rejectsHead("fractional head seq", [SUITE_ID, "", 1.5, digest], "seq");
  await rejectsHead(
    "uppercase prev head",
    [SUITE_ID, digest.toUpperCase(), 2, digest],
    "prevHeadHashHex",
  );
  await rejectsHead("short prev head", [SUITE_ID, digest.slice(0, 62), 2, digest], "prevHeadHashHex");
  await rejectsHead(
    "uppercase row digest",
    [SUITE_ID, "", 1, digest.toUpperCase()],
    "rowDigestHex",
  );
  // 上界の内側は受理される(MAX_SAFE_INTEGER 自身 — §2.1 の境界の裏側)
  const boundary = await computeAuditRowDigest({ ...base, serverTs: Number.MAX_SAFE_INTEGER });
  c.push("audit-head: MAX_SAFE_INTEGER serverTs accepted", boundary.ok);
}

export async function auditHeadChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await chainVectorChecks(c);
  await nullVsEmptyChecks(c);
  await invalidInputChecks(c);
  return c.results;
}
