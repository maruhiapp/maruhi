// ChainHistoryIndex(CRYPTO_SPEC §6.3 / session-14 裁定 A)のチェック。
// 正規チェーン(chain-entries.json)と tenure 拡張チェーン
// (value-signature.json の tenure_extension)に対して、seq → entry hash、
// 宣言ヘッド時点(inclusive)のメンバー状態・環境状態、tenure の分離を固定する。

import type { ChainEntry, ChainHistoryIndex, MemberStateAtSeq } from "../../src/index.ts";
import { soleDeviceOf, verifyChainWithHistory } from "../../src/index.ts";
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

/** 在籍開始時の端末 = 最初の鍵 1 つ(cap は構造的に (owner, all) — §6.2)と端末の時点照会。 */
function memberDeviceChecks(c: Checks, history: ChainHistoryIndex): void {
  const memberDevice = soleDeviceAt(history, MEMBER, 2);
  const expected = vectorKeys[MEMBER];
  if (memberDevice === undefined || expected === undefined) {
    c.push("history: member key binding matches chain keys", false, "device or keys missing");
    return;
  }
  c.push(
    "history: member key binding matches chain keys",
    memberDevice.keyFingerprintHex === expected.key_fingerprint_hex &&
      memberDevice.sigPubHex === expected.sig_pub_hex,
  );
  c.push(
    "history: first key has the structural cap (owner, all) from its add seq",
    memberDevice.roleCap === "owner" &&
      memberDevice.scope.kind === "all" &&
      memberDevice.addedSeq === 2,
  );
  // 端末の時点照会(§6.3-1): 同じ鍵は在籍区間の内側でのみ有効
  const deviceAt2 = history.deviceStateAt(MEMBER, expected.key_fingerprint_hex, 2);
  c.push(
    "history: member device state at its add seq carries the person's permission",
    deviceAt2?.permission.role === "member" && deviceAt2.tenureStartSeq === 2,
  );
  c.push(
    "history: member device state is undefined at the removal seq",
    history.deviceStateAt(MEMBER, expected.key_fingerprint_hex, 5) === undefined,
  );
}

/** `seq` 時点のメンバーの唯一の端末(不在・複数は undefined)。 */
function soleDeviceAt(history: ChainHistoryIndex, userId: string, seq: number) {
  const member = history.memberStateAt(userId, seq);
  return member === undefined ? undefined : soleDeviceOf(member);
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
  c.push(
    "history: tenure 1 keeps the original key",
    soleDeviceAt(extended, MEMBER, 4)?.keyFingerprintHex === oldKeys?.key_fingerprint_hex &&
      extended.memberStateAt(MEMBER, 4)?.tenureStartSeq === 2,
  );
  c.push(
    "history: tenure 2 binds the re-add key",
    soleDeviceAt(extended, MEMBER, EXTENSION_SEQ)?.keyFingerprintHex ===
      rejoined.key_fingerprint_hex &&
      extended.memberStateAt(MEMBER, EXTENSION_SEQ)?.tenureStartSeq === EXTENSION_SEQ,
  );
  c.push(
    "history: removal gap stays invalid between tenures",
    extended.memberStateAt(MEMBER, HEAD_SEQ) === undefined,
  );
}

/** 旧区間の鍵 × 新区間のヘッドは端末として無効(tenure 跨ぎ — §6.3-1)。 */
function tenureDeviceChecks(c: Checks, extended: ChainHistoryIndex): void {
  const rejoined = valueVectors.tenure_extension.rejoined_member;
  const oldFp = vectorKeys[MEMBER]?.key_fingerprint_hex ?? "";
  c.push(
    "history: tenure 1 key is not a device in tenure 2",
    extended.deviceStateAt(MEMBER, oldFp, EXTENSION_SEQ) === undefined,
  );
  c.push(
    "history: tenure 2 key is a device at the re-add seq",
    extended.deviceStateAt(MEMBER, rejoined.key_fingerprint_hex, EXTENSION_SEQ) !== undefined,
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

// ---------------------------------------------------------------------------
// 端末鍵(2026-09-19 DK — §6.2「端末の有効区間」/ §6.3「端末鍵の選択と実効権限」)。
// 派生チェーン device-ops(base 24、seq 25〜37 — 規約 28)に対して固定する

const ALL_MEMBER = "user-allmember-0013";
const OWNER_3 = "user-owner-0015";
const OWNER_2 = "user-owner-0014";

function deviceKey(label: string): { readonly fp: string; readonly sig: string } {
  const key = vectorKeys[label];
  if (key === undefined) {
    throw new Error(`device key ${label} missing`);
  }
  return { fp: key.key_fingerprint_hex, sig: key.sig_pub_hex };
}

function deviceIntervalChecks(c: Checks, history: ChainHistoryIndex): void {
  const cibox = deviceKey("user-allmember-0013@ci-box"); // seq 27 追加、seq 37 失効
  const first = deviceKey(ALL_MEMBER); // 最初の鍵(seq 16)
  c.push("history: device-ops head seq", history.headSeq === 37);
  // add_device 自身の seq で有効(inclusive)。直前は無効
  c.push(
    "history: second device absent before its add_device seq",
    history.deviceStateAt(ALL_MEMBER, cibox.fp, 26) === undefined &&
      history.memberStateAt(ALL_MEMBER, 26)?.devices.size === 1,
  );
  const at27 = history.deviceStateAt(ALL_MEMBER, cibox.fp, 27);
  c.push(
    "history: second device valid at its add_device seq with its cap",
    at27?.device.roleCap === "member" &&
      at27.device.scope.kind === "listed" &&
      at27.device.addedSeq === 27 &&
      at27.tenureStartSeq === 16 &&
      history.memberStateAt(ALL_MEMBER, 27)?.devices.size === 2,
  );
  // revoke_device 自身の seq で無効(inclusive)。人は在籍のまま、最初の鍵は残る
  c.push(
    "history: second device valid just before its revoke seq",
    history.deviceStateAt(ALL_MEMBER, cibox.fp, 36) !== undefined,
  );
  c.push(
    "history: second device invalid at its revoke seq while the person stays",
    history.deviceStateAt(ALL_MEMBER, cibox.fp, 37) === undefined &&
      history.deviceStateAt(ALL_MEMBER, first.fp, 37) !== undefined &&
      history.memberStateAt(ALL_MEMBER, 37)?.devices.size === 1,
  );
  // 失効済み端末の鍵も FP で引ける(§6.3-1 の鍵選択は全区間 — 有効性は deviceStateAt)
  c.push(
    "history: revoked device key stays resolvable by fingerprint",
    history.sigKeyByFingerprint(ALL_MEMBER, cibox.fp) === cibox.sig,
  );
  c.push(
    "history: device key is bound to its own user only",
    history.sigKeyByFingerprint(OWNER, cibox.fp) === undefined &&
      history.deviceStateAt(OWNER, cibox.fp, 30) === undefined,
  );
}

function effectivePermissionChecks(c: Checks, history: ChainHistoryIndex): void {
  const cibox = deviceKey("user-allmember-0013@ci-box");
  const readerCap = deviceKey("user-owner-0015@reader-cap"); // cap (reader, all) — seq 29
  const phone = deviceKey("user-owner-0001@phone"); // cap (owner, listed{}) — seq 26〜34
  // (min(人の role, role_cap), 人の scope ∩ 端末 scope)
  const ciAt28 = history.deviceStateAt(ALL_MEMBER, cibox.fp, 28);
  c.push(
    "history: effective scope is the intersection with the device scope",
    ciAt28?.permission.role === "member" &&
      ciAt28.permission.scope.kind === "listed" &&
      ciAt28.permission.scope.environmentIds.join(",") === "env-dev-0002,env-stage-0003" &&
      history.memberStateAt(ALL_MEMBER, 28)?.scope.kind === "all",
  );
  const readerAt29 = history.deviceStateAt(OWNER_3, readerCap.fp, 29);
  c.push(
    "history: effective role is min(person role, role cap)",
    readerAt29?.permission.role === "reader" &&
      readerAt29.permission.scope.kind === "all" &&
      history.memberStateAt(OWNER_3, 29)?.role === "owner",
  );
  const phoneAt30 = history.deviceStateAt(OWNER, phone.fp, 30);
  c.push(
    "history: empty listed device scope yields an empty effective scope",
    phoneAt30?.permission.role === "owner" &&
      phoneAt30.permission.scope.kind === "listed" &&
      phoneAt30.permission.scope.environmentIds.length === 0,
  );
  // 最初の鍵の実効権限 = 人の権限(cap (owner, all) は上限なし)
  const firstOwner2 = deviceKey(OWNER_2);
  c.push(
    "history: first key carries the person's full permission",
    history.deviceStateAt(OWNER_2, firstOwner2.fp, 37)?.permission.role === "owner",
  );
}

export async function chainHistoryChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const history = await canonicalHistory();
  entryHashChecks(c, history);
  memberBoundaryChecks(c, history);
  memberDeviceChecks(c, history);
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
  tenureDeviceChecks(c, extended);
  tenureKeyLookupChecks(c, extended);
  const deviceOps = await extendedVectorChainHistory("device-ops");
  deviceIntervalChecks(c, deviceOps);
  effectivePermissionChecks(c, deviceOps);
  return c.results;
}
