// ChainHistoryIndex(CRYPTO_SPEC §6.3 / session-14 裁定 A)のチェック。
// 正規チェーン(chain-entries.json)と tenure 拡張チェーン
// (value-signature.json の tenure_extension)に対して、seq → entry hash、
// 宣言ヘッド時点(inclusive)のメンバー状態・環境状態、tenure の分離を固定する。

import type { ChainEntry, ChainHistoryIndex } from "../../src/index.ts";
import { verifyChainWithHistory } from "../../src/index.ts";
import valueVectors from "../../test-vectors/value-signature.json" with { type: "json" };
import { toTypedEntry, typedEntries, vectorEntries, vectorKeys } from "./chain-vector.ts";
import { type CheckResult, Checks } from "./support.ts";

const OWNER = "user-owner-0001";
const MEMBER = "user-member-0002";
const ADMIN = "user-admin-0003";

/** tenure_extension のエントリ(seq 13 の新鍵 re-add)を型付きで得る。 */
export function tenureExtensionEntry(): ChainEntry {
  const raw = valueVectors.tenure_extension.entry;
  return toTypedEntry({
    seq: raw.seq,
    suite: raw.suite,
    prev_hash_hex: raw.prev_hash_hex,
    op: raw.op,
    actor: raw.actor,
    payload: raw.payload,
    timestamp_ms: raw.timestamp_ms,
    payload_bytes_hex: raw.payload_bytes_hex,
    signed_bytes_hex: raw.signed_bytes_hex,
    signature_hex: raw.signature_hex,
    entry_bytes_hex: raw.entry_bytes_hex,
    entry_hash_hex: raw.entry_hash_hex,
  });
}

/** 正規 12 エントリチェーンの検証済み履歴索引。 */
export async function canonicalHistory(): Promise<ChainHistoryIndex> {
  const result = await verifyChainWithHistory(typedEntries);
  if (!result.ok) {
    throw new Error("canonical chain failed verification");
  }
  return result.value.history;
}

/** 正規 12 エントリ + seq 13 re-add の派生チェーンの検証済み履歴索引。 */
export async function extendedHistory(): Promise<ChainHistoryIndex> {
  const result = await verifyChainWithHistory([...typedEntries, tenureExtensionEntry()]);
  if (!result.ok) {
    throw new Error("tenure-extension chain failed verification");
  }
  return result.value.history;
}

function entryHashChecks(c: Checks, history: ChainHistoryIndex): void {
  c.push("history: head seq", history.headSeq === 12);
  c.push(
    "history: head hash",
    history.headHashHex === vectorEntries[vectorEntries.length - 1]?.entry_hash_hex,
  );
  for (const vector of vectorEntries) {
    c.push(
      `history: entry hash at seq ${vector.seq}`,
      history.entryHashAt(vector.seq) === vector.entry_hash_hex,
    );
  }
  c.push("history: entry hash at seq 0 is undefined", history.entryHashAt(0) === undefined);
  c.push("history: entry hash beyond head is undefined", history.entryHashAt(13) === undefined);
  c.push(
    "history: entry hash at non-integer seq is undefined",
    history.entryHashAt(3.5) === undefined,
  );
}

function memberInclusiveChecks(c: Checks, history: ChainHistoryIndex): void {
  // genesis 自身の seq で owner 有効(inclusive)
  c.push("history: owner valid at genesis seq", history.memberStateAt(OWNER, 1)?.role === "owner");
  // add_member 自身の seq で対象有効(inclusive)。seq 1 では未加入
  c.push("history: member absent before add", history.memberStateAt(MEMBER, 1) === undefined);
  const memberAt2 = history.memberStateAt(MEMBER, 2);
  c.push(
    "history: member valid at its own add seq",
    memberAt2?.role === "member" && memberAt2.tenureStartSeq === 2,
  );
  c.push(
    "history: member key binding matches chain keys",
    memberAt2?.keyFingerprintHex === vectorKeys[MEMBER]?.key_fingerprint_hex &&
      memberAt2?.sigPubHex === vectorKeys[MEMBER]?.sig_pub_hex,
  );
  // remove_member 自身の seq で対象無効(inclusive)。直前 seq までは有効
  c.push(
    "history: member valid just before removal",
    history.memberStateAt(MEMBER, 4) !== undefined,
  );
  c.push(
    "history: member invalid at its removal seq",
    history.memberStateAt(MEMBER, 5) === undefined,
  );
  c.push("history: member invalid after removal", history.memberStateAt(MEMBER, 12) === undefined);
  // change_role 自身の seq で新 role 有効(inclusive)。add 時は reader
  c.push("history: admin absent before add", history.memberStateAt(ADMIN, 5) === undefined);
  c.push(
    "history: admin is reader at its add seq",
    history.memberStateAt(ADMIN, 6)?.role === "reader",
  );
  c.push(
    "history: admin has new role at its change_role seq",
    history.memberStateAt(ADMIN, 7)?.role === "admin",
  );
  c.push("history: admin keeps role at head", history.memberStateAt(ADMIN, 12)?.role === "admin");
}

function environmentInclusiveChecks(c: Checks, history: ChainHistoryIndex): void {
  // create_environment 自身の seq でエポック 1 有効(inclusive)。前 seq は未作成
  c.push(
    "history: environment absent before create",
    history.environmentStateAt("env-prod-0001", 2) === undefined,
  );
  const prodAt3 = history.environmentStateAt("env-prod-0001", 3);
  c.push(
    "history: environment epoch 1 at its create seq",
    prodAt3?.createdAtSeq === 3 && prodAt3?.currentEpoch === 1,
  );
  // rotate_epoch 自身の seq で新エポック有効(inclusive)
  c.push(
    "history: new epoch at its rotate seq",
    history.environmentStateAt("env-prod-0001", 4)?.currentEpoch === 2,
  );
  c.push(
    "history: epoch stays current at head",
    history.environmentStateAt("env-prod-0001", 12)?.currentEpoch === 2,
  );
  c.push(
    "history: dev environment created at seq 8",
    history.environmentStateAt("env-dev-0002", 8)?.currentEpoch === 1 &&
      history.environmentStateAt("env-dev-0002", 7) === undefined,
  );
  c.push(
    "history: dev epoch 2 from seq 10",
    history.environmentStateAt("env-dev-0002", 9)?.currentEpoch === 1 &&
      history.environmentStateAt("env-dev-0002", 10)?.currentEpoch === 2,
  );
  c.push(
    "history: stage stays epoch 1",
    history.environmentStateAt("env-stage-0003", 12)?.currentEpoch === 1,
  );
  c.push(
    "history: unknown environment is undefined",
    history.environmentStateAt("env-ghost-9999", 12) === undefined,
  );
}

function keyLookupChecks(c: Checks, history: ChainHistoryIndex): void {
  c.push(
    "history: sig key by fingerprint",
    history.sigKeyByFingerprint(OWNER, vectorKeys[OWNER]?.key_fingerprint_hex ?? "") ===
      vectorKeys[OWNER]?.sig_pub_hex,
  );
  c.push(
    "history: removed member's key stays resolvable",
    history.sigKeyByFingerprint(MEMBER, vectorKeys[MEMBER]?.key_fingerprint_hex ?? "") ===
      vectorKeys[MEMBER]?.sig_pub_hex,
  );
  c.push(
    "history: unknown fingerprint is undefined",
    history.sigKeyByFingerprint(OWNER, "00".repeat(16)) === undefined,
  );
  c.push(
    "history: unknown user is undefined",
    history.sigKeyByFingerprint("user-ghost-0042", vectorKeys[OWNER]?.key_fingerprint_hex ?? "") ===
      undefined,
  );
}

function tenureChecks(c: Checks, extended: ChainHistoryIndex): void {
  const rejoined = valueVectors.tenure_extension.rejoined_member;
  const oldKeys = vectorKeys[MEMBER];
  // remove → re-add は別 tenure: 旧区間(seq 2〜4)は旧鍵、新区間(seq 13〜)は新鍵
  const tenure1 = extended.memberStateAt(MEMBER, 4);
  const tenure2 = extended.memberStateAt(MEMBER, 13);
  c.push(
    "history: tenure 1 keeps the original key",
    tenure1?.keyFingerprintHex === oldKeys?.key_fingerprint_hex && tenure1?.tenureStartSeq === 2,
  );
  c.push(
    "history: tenure 2 binds the re-add key",
    tenure2?.keyFingerprintHex === rejoined.key_fingerprint_hex && tenure2?.tenureStartSeq === 13,
  );
  c.push(
    "history: removal gap stays invalid between tenures",
    extended.memberStateAt(MEMBER, 12) === undefined,
  );
  // 同じ user_id の両 tenure の鍵が FP で個別に引ける(dedupe で tenure を消さない)
  c.push(
    "history: both tenures' keys resolvable by fingerprint",
    extended.sigKeyByFingerprint(MEMBER, oldKeys?.key_fingerprint_hex ?? "") ===
      oldKeys?.sig_pub_hex &&
      extended.sigKeyByFingerprint(MEMBER, rejoined.key_fingerprint_hex) === rejoined.sig_pub_hex,
  );
}

export async function chainHistoryChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const history = await canonicalHistory();
  entryHashChecks(c, history);
  memberInclusiveChecks(c, history);
  environmentInclusiveChecks(c, history);
  keyLookupChecks(c, history);
  const extended = await extendedHistory();
  c.push("history: extension head seq", extended.headSeq === 13);
  c.push(
    "history: extension entry hash at seq 13",
    extended.entryHashAt(13) === valueVectors.tenure_extension.entry.entry_hash_hex,
  );
  tenureChecks(c, extended);
  return c.results;
}
