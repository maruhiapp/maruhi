// ChainHistoryIndex(CRYPTO_SPEC §6.3 / session-14 裁定 A)のチェック。
// 正規チェーン(chain-entries.json)と tenure 拡張チェーン
// (value-signature.json の tenure_extension)に対して、seq → entry hash、
// 宣言ヘッド時点(inclusive)のメンバー状態・環境状態、tenure の分離を固定する。

import type { ChainEntry, ChainHistoryIndex, MemberStateAtSeq } from "../../src/index.ts";
import { verifyChainWithHistory } from "../../src/index.ts";
import valueVectors from "../../test-vectors/value-signature.json" with { type: "json" };
import {
  toTypedEntry,
  typedEntries,
  vectorEntries,
  vectorExtendedChains,
  vectorKeys,
} from "./chain-vector.ts";
import { type CheckResult, Checks } from "./support.ts";

const OWNER = "user-owner-0001";
const MEMBER = "user-member-0002";
const ADMIN = "user-admin-0003";
const DEV_MEMBER = "user-devmember-0010";
/** 正規チェーンのヘッド seq(chain-entries.json — 2026-09-14 ES + PF1 で 24)。 */
const HEAD_SEQ = 24;
/** tenure_extension(value-signature.json)の re-add エントリの seq(= ヘッドの次)。 */
const EXTENSION_SEQ = HEAD_SEQ + 1;

/** tenure_extension のエントリ(seq 25 の新鍵 re-add)を型付きで得る。 */
function tenureExtensionEntry(): ChainEntry {
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

/** 正規 24 エントリチェーンの検証済み履歴索引。 */
export async function canonicalHistory(): Promise<ChainHistoryIndex> {
  const result = await verifyChainWithHistory(typedEntries);
  if (!result.ok) {
    throw new Error("canonical chain failed verification");
  }
  return result.value.history;
}

/**
 * chain-entries.json の派生チェーン(extended_chains)の検証済み履歴索引。
 * チェックポイント束縛のマニフェスト検証(§4.3 (2) — env-manifest.ts)が
 * checkpoint-boundary-* を照合先チェーンとして使う。
 */
export async function extendedVectorChainHistory(name: string): Promise<ChainHistoryIndex> {
  const extended = vectorExtendedChains[name];
  if (extended === undefined) {
    throw new Error(`extended chain ${name} missing`);
  }
  const result = await verifyChainWithHistory([
    ...typedEntries.slice(0, extended.base_seq),
    ...extended.entries.map((entry) => toTypedEntry(entry)),
  ]);
  if (!result.ok) {
    throw new Error(`extended chain ${name} failed verification`);
  }
  return result.value.history;
}

/** 正規 24 エントリ + seq 25 re-add の派生チェーンの検証済み履歴索引。 */
export async function extendedHistory(): Promise<ChainHistoryIndex> {
  const result = await verifyChainWithHistory([...typedEntries, tenureExtensionEntry()]);
  if (!result.ok) {
    throw new Error("tenure-extension chain failed verification");
  }
  return result.value.history;
}

function entryHashChecks(c: Checks, history: ChainHistoryIndex): void {
  c.push("history: head seq", history.headSeq === HEAD_SEQ);
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
  c.push(
    "history: entry hash beyond head is undefined",
    history.entryHashAt(HEAD_SEQ + 1) === undefined,
  );
  c.push(
    "history: entry hash at non-integer seq is undefined",
    history.entryHashAt(3.5) === undefined,
  );
}

function memberBoundaryChecks(c: Checks, history: ChainHistoryIndex): void {
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
  c.push(
    "history: member invalid after removal",
    history.memberStateAt(MEMBER, HEAD_SEQ) === undefined,
  );
}

function roleChangeBoundaryChecks(c: Checks, history: ChainHistoryIndex): void {
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
  c.push(
    "history: admin keeps role at head",
    history.memberStateAt(ADMIN, HEAD_SEQ)?.role === "admin",
  );
}

/** (role, scope) の変化点(§6.2 — 2026-09-14 ES / PF1 の提案経由適用)。 */
/** listed scope の環境 id 列(all / 不在は undefined)。 */
function listed(state: MemberStateAtSeq | undefined): readonly string[] | undefined {
  return state?.scope.kind === "listed" ? state.scope.environmentIds : undefined;
}

function scopeBoundaryChecks(c: Checks, history: ChainHistoryIndex): void {
  // genesis 由来の owner / 旧形式相当の add_member は scope = all
  c.push("history: owner scope is all", history.memberStateAt(OWNER, 1)?.scope.kind === "all");
  c.push("history: admin scope is all", history.memberStateAt(ADMIN, 6)?.scope.kind === "all");
  // seq 13: listed{dev} の member として加入(inclusive)
  c.push(
    "history: dev member absent before add",
    history.memberStateAt(DEV_MEMBER, 12) === undefined,
  );
  const at13 = history.memberStateAt(DEV_MEMBER, 13);
  c.push(
    "history: dev member listed{dev} at its add seq",
    at13?.role === "member" && listed(at13)?.join(",") === "env-dev-0002",
  );
  // seq 17: change_role(scope だけ拡大 — {dev} → {dev, stage})は自身の seq で有効
  c.push(
    "history: dev member scope unchanged just before change_role",
    listed(history.memberStateAt(DEV_MEMBER, 16))?.join(",") === "env-dev-0002",
  );
  const at17 = history.memberStateAt(DEV_MEMBER, 17);
  c.push(
    "history: dev member widened scope at its change_role seq",
    at17?.role === "member" && listed(at17)?.join(",") === "env-dev-0002,env-stage-0003",
  );
}

/** 提案経由の適用(PF1): 変化点は定足数に達した approve エントリの seq(inclusive)。 */
function proposalApplyBoundaryChecks(c: Checks, history: ChainHistoryIndex): void {
  // seq 21 の propose は状態を変えず、seq 22 の approve(定足数到達)で内側 change_role
  // (reader / listed{dev})が適用される
  const at21 = history.memberStateAt(DEV_MEMBER, 21);
  c.push(
    "history: propose does not change the target",
    at21?.role === "member" && listed(at21)?.join(",") === "env-dev-0002,env-stage-0003",
  );
  const at22 = history.memberStateAt(DEV_MEMBER, 22);
  c.push(
    "history: quorum approve applies the inner change_role at its own seq",
    at22?.role === "reader" && listed(at22)?.join(",") === "env-dev-0002",
  );
  c.push(
    "history: applied change persists at head",
    history.memberStateAt(DEV_MEMBER, HEAD_SEQ)?.role === "reader",
  );
}

function environmentCreateRotateChecks(c: Checks, history: ChainHistoryIndex): void {
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
    history.environmentStateAt("env-prod-0001", HEAD_SEQ)?.currentEpoch === 2,
  );
}

function environmentCoverageChecks(c: Checks, history: ChainHistoryIndex): void {
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
    history.environmentStateAt("env-stage-0003", HEAD_SEQ)?.currentEpoch === 1,
  );
  c.push(
    "history: unknown environment is undefined",
    history.environmentStateAt("env-ghost-9999", HEAD_SEQ) === undefined,
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

function tenureBoundaryChecks(c: Checks, extended: ChainHistoryIndex): void {
  const rejoined = valueVectors.tenure_extension.rejoined_member;
  const oldKeys = vectorKeys[MEMBER];
  // remove → re-add は別 tenure: 旧区間(seq 2〜4)は旧鍵、新区間(seq 25〜)は新鍵
  const tenure1 = extended.memberStateAt(MEMBER, 4);
  const tenure2 = extended.memberStateAt(MEMBER, EXTENSION_SEQ);
  c.push(
    "history: tenure 1 keeps the original key",
    tenure1?.keyFingerprintHex === oldKeys?.key_fingerprint_hex && tenure1?.tenureStartSeq === 2,
  );
  c.push(
    "history: tenure 2 binds the re-add key",
    tenure2?.keyFingerprintHex === rejoined.key_fingerprint_hex &&
      tenure2?.tenureStartSeq === EXTENSION_SEQ,
  );
  c.push(
    "history: removal gap stays invalid between tenures",
    extended.memberStateAt(MEMBER, HEAD_SEQ) === undefined,
  );
}

function tenureKeyLookupChecks(c: Checks, extended: ChainHistoryIndex): void {
  const rejoined = valueVectors.tenure_extension.rejoined_member;
  const oldKeys = vectorKeys[MEMBER];
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
  memberBoundaryChecks(c, history);
  roleChangeBoundaryChecks(c, history);
  scopeBoundaryChecks(c, history);
  proposalApplyBoundaryChecks(c, history);
  environmentCreateRotateChecks(c, history);
  environmentCoverageChecks(c, history);
  keyLookupChecks(c, history);
  const extended = await extendedHistory();
  c.push("history: extension head seq", extended.headSeq === EXTENSION_SEQ);
  c.push(
    "history: extension entry hash at the re-add seq",
    extended.entryHashAt(EXTENSION_SEQ) === valueVectors.tenure_extension.entry.entry_hash_hex,
  );
  tenureBoundaryChecks(c, extended);
  tenureKeyLookupChecks(c, extended);
  return c.results;
}
