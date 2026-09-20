// CRYPTO_SPEC §6.3: クライアント検証 — prev_hash 連続性、Ed25519 署名、
// §6.2 の role / scope / 四眼の規則を全エントリで検証し、検証済みチェーンから
// 現メンバー集合(role + scope 付き)・有効 grant_server 集合・観測エポック・
// 四眼の方針と pending 提案を導出する。
//
// 検証順序(認可系テストベクターの expected_reason と対応):
//   1. フレーミング(suite / seq / genesis 位置 / prev_hash)
//   2. payload の構造検証(hex 長・role 値・数値範囲・scope 構造・内側 op の形状)
//      → invalid-payload
//   3. actor 解決(現メンバーか / 申告 FP が登録鍵と一致するか)
//      → actor-not-member / actor-key-mismatch
//   4. 署名検証(actor の登録 sig 公開鍵)→ bad-signature
//   5. 認可 + 状態遷移(role 規則 → 四眼 → 対象の存在・最後の owner 保護・scope …)
//
// 2026-09-14 ES + PF1: 認可段は「role 規則 / 合意規則 / 適用」の 3 相に分け、
// 直接追記・propose(内側 op の事前検査)・approve(定足数到達時の適用)が同じ
// 相関数を共有する。原則 1(権限変更の環境集合の包含)と原則 2(署名者集合 S
// の owner 票数)はそれぞれ 1 つの導出関数(permissionChangeEnvironments /
// countOwnerVotes)で表し、op ごとの if 列挙にしない。
//
// 2026-09-19 DK(端末鍵 — §6.2「端末鍵」): メンバーは端末鍵の集合を持ち、actor の解決は
// (user_id, FP) で端末を選ぶ。認可判定の主体 ActorContext は**署名した端末の実効権限**
// (effectivePermissionOf — chain-device.ts)を持ち、role 規則・原則 1・環境対象 op・
// 四眼の票はすべてそれに対して判定する(人の (role, scope) を直接は使わない)。

import { concatBytes, decodeHex, encodeHex, utf8Encode } from "./bytes.ts";
import { canonicalChainSignedBytes, computeChainEntryHash } from "./chain-canonical.ts";
import {
  type ChainDevice,
  type EffectivePermission,
  FIRST_DEVICE_CAP,
  ROLE_RANK,
  capWithinCap,
  effectivePermissionOf,
  soleDeviceOf,
} from "./chain-device.ts";
import { ChainHistoryBuilder, type ChainHistoryIndex } from "./chain-history.ts";
import {
  APPROVAL_TARGET_OPS,
  type ApprovalPolicy,
  type ApprovalTargetOp,
  type ApprovalVote,
  type ChainEntry,
  type ChainMember,
  type ChainState,
  type CheckpointEnvironmentEntry,
  type EnvironmentCheckpointState,
  type PendingProposal,
  type ProposableOperation,
  type Role,
  type ServerGrant,
} from "./chain-types.ts";
import type { ChainInvalidReason, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import {
  ALL_SCOPE,
  type EnvironmentSet,
  MAX_SCOPE_ENVIRONMENTS,
  memberScopeOf,
  scopeAsEnvironmentSet,
  scopeContainsEnvironmentSet,
  scopeIncludesEnvironment,
  scopeShapeOk,
  symmetricDifferenceEnvironmentSets,
  unionEnvironmentSets,
} from "./member-scope.ts";
import { SUITE_ID } from "./suite.ts";

const GENESIS_PREV_HASH = "0".repeat(64);
const ROLES: readonly Role[] = ["owner", "admin", "member", "reader"];
const FINGERPRINT_BYTES = 16;
const SIGNATURE_BYTES = 64;
const SHA256_BYTES = 32;
// フィールドサイズ上限(CRYPTO_SPEC §6.1): チェーン有効性の
// 合意規則。巨大 payload による検証クライアントの資源消費(可用性)対策
const MAX_FIELD_BYTES = 1024;
// lease_policy の上限(CRYPTO_SPEC §6.2): 要素 8・要素あたり claim
// 制約 8(各文字列は MAX_FIELD_BYTES)。仕様適合 grant_server エントリの正規化
// サイズが §6.4 の受理ポリシー上限を数学的に下回り続けるように選ばれた合意規則
const MAX_LEASE_POLICY_ISSUERS = 8;
const MAX_LEASE_CLAIM_CONSTRAINTS = 8;
// 四眼の必要承認数(§6.2): 0 = オフ、それ以外は 2 以上
const MIN_ACTIVE_REQUIRED_APPROVALS = 2;
// revoke_device の FP リスト上限(§6.2 — 1 要素以上・256 要素以下・重複無効)
const MAX_REVOKE_DEVICE_FINGERPRINTS = 256;

interface MutableEnvironmentState {
  currentEpoch: number;
  readonly createdAtSeq: number;
  readonly epochStartSeqs: Map<number, number>;
  readonly dekCommitments: Map<number, string>;
}

/** pending 提案(§6.2 の検証状態)。approvals は受理済み approve の署名 (user_id, 鍵 FP)(順序付き)。 */
interface MutablePendingProposal {
  readonly proposalSeq: number;
  readonly proposalHashHex: string;
  readonly proposerUserId: string;
  readonly proposerKeyFingerprintHex: string;
  readonly proposerRoleAtProposal: Role;
  readonly inner: ProposableOperation;
  readonly expiresAtMs: number;
  readonly approvals: ApprovalVote[];
}

interface MutableChainState {
  readonly members: Map<string, ChainMember>;
  readonly serverGrants: Map<string, ServerGrant>;
  // 環境集合(§6.2 create_environment の導出)。チェーンは環境の削除を観測しない
  // (削除はデータプレーン操作)ため、このマップ自体が「履歴全体の使用済み ID」
  // でもあり、duplicate-environment の判定に追加の索引を要しない
  readonly environments: Map<string, MutableEnvironmentState>;
  // 環境ごとの最新チェックポイントタプル(§6.2 checkpoint の導出状態 —
  // checkpoint-regression の比較対象と §6.3 チェックポイント整合の基準)
  readonly checkpoints: Map<string, EnvironmentCheckpointState>;
  // 現メンバー集合の**全端末鍵**の enc / sig 公開鍵の索引(メンバー鍵の一意性 — §6.2。
  // 2026-09-19 DK で端末集合へ拡張)。本規則自体が「各鍵は高々 1 端末に属する」を
  // 不変条件にするため、remove_member / revoke_device での Set 削除は他の端末の鍵を
  // 消さない(健全)。
  // hex は §6.1 の形状検証(decodeHex = 小文字のみ)を通った正規形なので
  // 文字列一致 = バイト一致
  readonly memberEncPubs: Set<string>;
  readonly memberSigPubs: Set<string>;
  // 四眼(§6.2): 現方針(null = オフ)と pending 提案(提案エントリ hash → 提案)
  approvalPolicy: ApprovalPolicy | null;
  readonly pendingProposals: Map<string, MutablePendingProposal>;
}

/**
 * 認可判定の主体(直接追記の actor、または提案の適用時の提案者): 人(user_id)と
 * 署名した端末、およびその端末の実効権限(§6.2 — 人の (role, scope) は ChainMember に
 * あるが、検査へ渡すのは brand 付きの EffectivePermission のみ)。
 */
interface ActorContext {
  readonly userId: string;
  readonly device: ChainDevice;
  readonly permission: EffectivePermission;
}

/** 適用された(履歴索引へ記録すべき)op とその帰属主体。 */
interface AppliedOperation {
  readonly operation: ProposableOperation;
  readonly actorUserId: string;
}

// 形状検証の各述語は、TS 型が主張する形と実際の実行時入力(サーバー配布の
// JSON をキャストしたもの)が乖離していても例外を投げないよう、unknown を
// 受けて実行時型から検査する(悪意あるチェーンデータは必ず invalid-payload に
// 落とす。throw で検証を中断させない)

function withinFieldBytes(value: string): boolean {
  // UTF-8 バイト数 ≥ コード単位数なので、まず安価な length で弾いてから
  // 上限以下の候補だけ実エンコードで確定する(巨大文字列の確保を避ける)
  return value.length <= MAX_FIELD_BYTES && utf8Encode(value).length <= MAX_FIELD_BYTES;
}

/** 非空かつ UTF-8 で MAX_FIELD_BYTES 以下の自由文字列フィールド(ID・reason 等) */
function isBoundedId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && withinFieldBytes(value);
}

function isHexOfLength(value: unknown, bytes: number): boolean {
  // 期待長と異なる文字列は decodeHex(正規表現スキャン + 確保)に入る前に O(1) で
  // 弾く(巨大 hex 文字列での CPU / メモリ消費を防ぐ fail-fast)
  if (typeof value !== "string" || value.length !== bytes * 2) {
    return false;
  }
  const decoded = decodeHex(value);
  return decoded !== null && decoded.length === bytes;
}

function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

function isApprovalTargetOp(value: unknown): value is ApprovalTargetOp {
  return typeof value === "string" && (APPROVAL_TARGET_OPS as readonly string[]).includes(value);
}

function atLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

async function userFingerprintHex(encPubHex: string, sigPubHex: string): Promise<string> {
  // 呼び出し前に hex 形状は検証済み(32B ずつ)。FP = SHA-256(enc || sig)[:16]
  const enc = decodeHex(encPubHex) ?? new Uint8Array(0);
  const sig = decodeHex(sigPubHex) ?? new Uint8Array(0);
  const digest = await sha256(concatBytes(enc, sig));
  return encodeHex(digest.slice(0, FINGERPRINT_BYTES));
}

function checkFraming(
  entry: ChainEntry,
  expectedSeq: number,
  expectedPrevHash: string,
): ChainInvalidReason | null {
  if (entry.suite !== SUITE_ID) {
    return "bad-suite";
  }
  if (entry.seq !== expectedSeq) {
    return "bad-seq";
  }
  if ((expectedSeq === 1) !== (entry.op === "genesis")) {
    return "bad-genesis";
  }
  if (entry.prevHashHex !== expectedPrevHash) {
    return "bad-prev-hash";
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function checkPayloadShape(entry: ChainEntry): ChainInvalidReason | null {
  if (!Number.isSafeInteger(entry.timestampMs) || entry.timestampMs < 0) {
    return "invalid-payload";
  }
  // actor FP(16B)と署名(64B)は §6.1 の固定長 hex。厳密長で fail-fast し、
  // 巨大 hex 文字列が decodeHex や正規化に到達しないようにする
  if (
    !isRecord(entry.actor) ||
    !isBoundedId(entry.actor.userId) ||
    !isHexOfLength(entry.actor.keyFingerprintHex, FINGERPRINT_BYTES)
  ) {
    return "invalid-payload";
  }
  if (!isHexOfLength(entry.signatureHex, SIGNATURE_BYTES)) {
    return "invalid-payload";
  }
  return operationShapeOk(entry.op, entry.payload) ? null : "invalid-payload";
}

function shapeGenesis(p: { encPubHex: unknown; sigPubHex: unknown }): boolean {
  return isHexOfLength(p.encPubHex, 32) && isHexOfLength(p.sigPubHex, 32);
}

/** scope の 2 フィールド(§6.2 の構造規則 — 認可判定に先行)。 */
function shapeScope(p: { scopeKind: unknown; scopeEnvironmentIds: unknown }): boolean {
  return scopeShapeOk(p.scopeKind, p.scopeEnvironmentIds, isBoundedId);
}

function shapeAddMember(p: {
  targetUserId: unknown;
  encPubHex: unknown;
  sigPubHex: unknown;
  role: unknown;
  scopeKind: unknown;
  scopeEnvironmentIds: unknown;
}): boolean {
  return isBoundedId(p.targetUserId) && shapeGenesis(p) && isRole(p.role) && shapeScope(p);
}

function shapeChangeRole(p: {
  targetUserId: unknown;
  newRole: unknown;
  scopeKind: unknown;
  scopeEnvironmentIds: unknown;
}): boolean {
  return isBoundedId(p.targetUserId) && isRole(p.newRole) && shapeScope(p);
}

function shapeCreateEnvironment(p: { environmentId: unknown; dekCommitmentHex: unknown }): boolean {
  // dek_commitment_hex は hex 小文字 64 文字(§6.2 の合意規則。形式検査は
  // payload 構造検査の段に属し、認可判定に先行する)
  return isBoundedId(p.environmentId) && isHexOfLength(p.dekCommitmentHex, SHA256_BYTES);
}

function shapeRotateEpoch(p: {
  environmentId: unknown;
  newEpoch: unknown;
  reason: unknown;
  dekCommitmentHex: unknown;
}): boolean {
  return (
    isBoundedId(p.environmentId) &&
    Number.isSafeInteger(p.newEpoch) &&
    (p.newEpoch as number) >= 1 &&
    typeof p.reason === "string" &&
    withinFieldBytes(p.reason) &&
    isHexOfLength(p.dekCommitmentHex, SHA256_BYTES)
  );
}

/**
 * lease_policy の 1 制約の形状(§6.2)。claim_name は識別子(非空)、claim_value は
 * データ位置(rotate_epoch の reason と同じく空文字列を許す — OIDC claim の値は
 * 空文字列でありうる)。どちらも §6.1 の 1024 バイト上限に服する
 */
function shapeLeaseClaimConstraint(value: unknown): boolean {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isBoundedId(value.claimName) &&
    typeof value.claimValue === "string" &&
    withinFieldBytes(value.claimValue)
  );
}

function shapeLeasePolicyIssuer(value: unknown): boolean {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isBoundedId(value.issuerUrl) &&
    isBoundedId(value.audience) &&
    Array.isArray(value.claimConstraints) &&
    value.claimConstraints.length <= MAX_LEASE_CLAIM_CONSTRAINTS &&
    value.claimConstraints.every((constraint) => shapeLeaseClaimConstraint(constraint))
  );
}

function shapeGrantServer(p: {
  serverEncPubHex: unknown;
  serverKeyFingerprintHex: unknown;
  scopeEnvironmentIds: unknown;
  leasePolicy: unknown;
}): boolean {
  return (
    isHexOfLength(p.serverEncPubHex, 32) &&
    isHexOfLength(p.serverKeyFingerprintHex, FINGERPRINT_BYTES) &&
    Array.isArray(p.scopeEnvironmentIds) &&
    p.scopeEnvironmentIds.length <= MAX_SCOPE_ENVIRONMENTS &&
    p.scopeEnvironmentIds.every((id) => isBoundedId(id)) &&
    // lease_policy(§6.2): 構造のみ合意規則(評価意味論は AUTH_SPEC §14)。
    // leasePolicy 欠落はここで invalid-payload になる
    Array.isArray(p.leasePolicy) &&
    p.leasePolicy.length <= MAX_LEASE_POLICY_ISSUERS &&
    p.leasePolicy.every((element) => shapeLeasePolicyIssuer(element))
  );
}

/**
 * checkpoint payload の構造検査(§6.2)。hex 長・数値範囲に加えて**重複
 * environment_id の拒否**も構造段に属する(仕様の「payload 構造検査」—
 * 同一環境の 2 エントリを許すと §6.3 の基準・checkpoint-regression の
 * 比較対象が非決定になる)。環境エントリ数の合意規則上限は置かない
 * (§6.2 — サイズはサーバー受理ポリシー〔§6.4 の 1 MiB〕が束縛する)
 */
function shapeCheckpointEnvironment(value: unknown): boolean {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isBoundedId(value.environmentId) &&
    Number.isSafeInteger(value.epoch) &&
    (value.epoch as number) >= 1 &&
    Number.isSafeInteger(value.manifestVersion) &&
    (value.manifestVersion as number) >= 1 &&
    isHexOfLength(value.manifestSigHashHex, SHA256_BYTES) &&
    isHexOfLength(value.valuesDigestHex, SHA256_BYTES)
  );
}

function shapeCheckpoint(p: { environments: unknown; auditHeadHashHex: unknown }): boolean {
  if (!Array.isArray(p.environments)) {
    return false;
  }
  if (!p.environments.every((entry) => shapeCheckpointEnvironment(entry))) {
    return false;
  }
  const ids = new Set<string>();
  for (const entry of p.environments as readonly { environmentId: string }[]) {
    if (ids.has(entry.environmentId)) {
      return false;
    }
    ids.add(entry.environmentId);
  }
  // audit_head_hash は空文字列(公証なし)または hex 小文字 64 文字のみ
  return p.auditHeadHashHex === "" || isHexOfLength(p.auditHeadHashHex, SHA256_BYTES);
}

/**
 * set_approval_policy の構造(§6.2): ops は対象になりうる op の閉集合の要素のみ
 * (重複は grant_server の scope と同じく集合として扱い、構造段では拒否しない)、
 * required_approvals は 0(オフ)または 2 以上の安全整数
 */
function shapeSetApprovalPolicy(p: { ops: unknown; requiredApprovals: unknown }): boolean {
  return (
    Array.isArray(p.ops) &&
    p.ops.every((op) => isApprovalTargetOp(op)) &&
    Number.isSafeInteger(p.requiredApprovals) &&
    ((p.requiredApprovals as number) === 0 ||
      (p.requiredApprovals as number) >= MIN_ACTIVE_REQUIRED_APPROVALS)
  );
}

/**
 * propose の構造(§6.2): 内側 op は propose / approve / withdraw 以外の既知 op で、
 * 内側 payload はその op の形状表を満たす(入れ子は 1 段 — 提案の入れ子は方針の
 * 対象になりえないため構造段で拒否し、再帰的な形状検査を持たない)。
 * expires_at_ms は非負の安全整数
 */
function shapePropose(p: { inner: unknown; expiresAtMs: unknown }): boolean {
  if (!isRecord(p.inner) || !isProposableOp(p.inner.op)) {
    return false;
  }
  return (
    operationShapeOk(p.inner.op, p.inner.payload) &&
    Number.isSafeInteger(p.expiresAtMs) &&
    (p.expiresAtMs as number) >= 0
  );
}

function shapeProposalRef(p: { proposalHashHex: unknown }): boolean {
  return isHexOfLength(p.proposalHashHex, SHA256_BYTES);
}

/**
 * add_device の構造(§6.2 — 2026-09-19 DK): 公開鍵は hex 小文字 64、role_cap は role 表の
 * 値、scope の 2 フィールドは環境スコープと同じ構造規則(`all` ⇒ 空リスト・256 以下・
 * 重複無効・`listed` の空リストは有効)
 */
function shapeAddDevice(p: {
  encPubHex: unknown;
  sigPubHex: unknown;
  roleCap: unknown;
  scopeKind: unknown;
  scopeEnvironmentIds: unknown;
}): boolean {
  return shapeGenesis(p) && isRole(p.roleCap) && shapeScope(p);
}

/**
 * revoke_device の構造(§6.2 — 2026-09-19 DK): 対象 user_id と、FP(hex 小文字 32)の
 * リスト(1 要素以上・256 要素以下・重複無効。順序は署名対象だが検証は集合として扱う)
 */
function shapeRevokeDevice(p: { targetUserId: unknown; deviceFingerprintsHex: unknown }): boolean {
  if (!isBoundedId(p.targetUserId) || !Array.isArray(p.deviceFingerprintsHex)) {
    return false;
  }
  const fps = p.deviceFingerprintsHex;
  if (fps.length < 1 || fps.length > MAX_REVOKE_DEVICE_FINGERPRINTS) {
    return false;
  }
  if (!fps.every((fp) => isHexOfLength(fp, FINGERPRINT_BYTES))) {
    return false;
  }
  return new Set(fps as readonly string[]).size === fps.length;
}

// op ごとの payload 形状述語(§6.1 / §6.2 の構造検査)。分岐でなく表引きにして
// op 追加時の検査漏れを型(網羅 Record)で防ぐ
const PAYLOAD_SHAPES: {
  readonly [K in ChainEntry["op"]]: (payload: Extract<ChainEntry, { op: K }>["payload"]) => boolean;
} = {
  genesis: shapeGenesis,
  add_member: shapeAddMember,
  remove_member: (p) => isBoundedId(p.targetUserId),
  change_role: shapeChangeRole,
  create_environment: shapeCreateEnvironment,
  rotate_epoch: shapeRotateEpoch,
  grant_server: shapeGrantServer,
  revoke_server: (p) => isHexOfLength(p.serverKeyFingerprintHex, FINGERPRINT_BYTES),
  checkpoint: shapeCheckpoint,
  set_approval_policy: shapeSetApprovalPolicy,
  propose: shapePropose,
  approve: shapeProposalRef,
  withdraw: shapeProposalRef,
  add_device: shapeAddDevice,
  revoke_device: shapeRevokeDevice,
};

const APPROVAL_OPS: readonly string[] = ["propose", "approve", "withdraw"];

function isKnownOp(op: unknown): op is ChainEntry["op"] {
  // 未知の op は表引きの**前**に membership で拒否する: TS 型は
  // op の網羅を主張するが、入力はサーバー配布 JSON のキャストであり乖離しうる。
  // 確認せずに PAYLOAD_SHAPES[op] を呼ぶと TypeError となり、「不正入力は
  // invalid-payload を返し throw しない」という公開 verifier の契約に反する。
  // Object.hasOwn は "__proto__" / "toString" 等のプロトタイプ由来の名前も
  // 自有プロパティでないとして正しく拒否する
  return typeof op === "string" && Object.hasOwn(PAYLOAD_SHAPES, op);
}

function isProposableOp(op: unknown): op is ProposableOperation["op"] {
  return isKnownOp(op) && !APPROVAL_OPS.includes(op);
}

function operationShapeOk(op: unknown, payload: unknown): boolean {
  if (!isKnownOp(op) || !isRecord(payload)) {
    return false;
  }
  return PAYLOAD_SHAPES[op](payload as never);
}

/** actor の登録 sig 公開鍵(hex)を解決する。genesis は payload で自己記述 */
async function resolveActorSigPub(
  entry: ChainEntry,
  state: MutableChainState,
): Promise<{ readonly sigPubHex: string } | { readonly reason: ChainInvalidReason }> {
  if (entry.op === "genesis") {
    const fp = await userFingerprintHex(entry.payload.encPubHex, entry.payload.sigPubHex);
    if (fp !== entry.actor.keyFingerprintHex) {
      return { reason: "actor-key-mismatch" };
    }
    return { sigPubHex: entry.payload.sigPubHex };
  }
  const record = state.members.get(entry.actor.userId);
  if (record === undefined) {
    return { reason: "actor-not-member" };
  }
  // 申告 FP が現在有効な端末を選ぶ(§6.2 — 失効した端末・未登録の鍵は actor-key-mismatch)
  const device = record.devices.get(entry.actor.keyFingerprintHex);
  if (device === undefined) {
    return { reason: "actor-key-mismatch" };
  }
  return { sigPubHex: device.sigPubHex };
}

async function verifyEntrySignature(entry: ChainEntry, sigPubHex: string): Promise<boolean> {
  const signature = decodeHex(entry.signatureHex);
  const publicKeyBytes = decodeHex(sigPubHex);
  if (signature === null || signature.length !== SIGNATURE_BYTES || publicKeyBytes === null) {
    return false;
  }
  try {
    // 正規化はこの try 内で行うこと(リファクタで外へ出さない): 巨大フィールド等で
    // エンコーダが投げる例外もここで bad-signature に封じ込め、verifyChain の
    // 「不信入力で throw しない」契約を保つ。ループ内の computeChainEntryHash は
    // ここで同一フィールドのエンコードが成功した後にのみ到達する
    const signedBytes = canonicalChainSignedBytes(entry);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes as BufferSource,
      "Ed25519",
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      signature as BufferSource,
      signedBytes as BufferSource,
    );
  } catch {
    return false;
  }
}

function ownersCount(state: MutableChainState): number {
  let count = 0;
  for (const member of state.members.values()) {
    if (member.role === "owner") {
      count += 1;
    }
  }
  return count;
}

/** 署名した端末の実効権限を持つ主体(§6.2 — effectivePermissionOf が唯一の計算点)。 */
function actorContextOf(member: ChainMember, device: ChainDevice): ActorContext {
  return { userId: member.userId, device, permission: effectivePermissionOf(member, device) };
}

/** 現メンバー集合の全端末鍵の索引へ端末の鍵を載せる / 外す(メンバー鍵の一意性 — §6.2)。 */
function indexDeviceKeys(state: MutableChainState, device: ChainDevice): void {
  state.memberEncPubs.add(device.encPubHex);
  state.memberSigPubs.add(device.sigPubHex);
}

function unindexDeviceKeys(state: MutableChainState, device: ChainDevice): void {
  state.memberEncPubs.delete(device.encPubHex);
  state.memberSigPubs.delete(device.sigPubHex);
}

/** 最初の端末鍵(genesis / add_member — cap は構造的に (owner, all))。 */
function firstDeviceOf(
  keys: { readonly encPubHex: string; readonly sigPubHex: string },
  keyFingerprintHex: string,
  addedSeq: number,
): ChainDevice {
  return {
    ...FIRST_DEVICE_CAP,
    encPubHex: keys.encPubHex,
    sigPubHex: keys.sigPubHex,
    keyFingerprintHex,
    addedSeq,
  };
}

// ---------------------------------------------------------------------------
// 原則 1 / 原則 2 の導出関数

/**
 * 原則 1(§6.2): op が権限を変える環境集合。role 表からの導出であり列挙ではない —
 * add_member = 新 scope、change_role = role が変わるなら 旧 ∪ 新・scope だけなら
 * 対称差、remove_member = 現 scope。`all` は U(将来環境を含む)として扱う
 * (集合代数は member-scope.ts)。target は呼び出し側が存在確認済み(不在は
 * unknown-target で先に落ちる — ここでは fail-closed に U として扱う)
 */
function permissionChangeEnvironments(
  operation: Extract<ProposableOperation, { op: "add_member" | "change_role" | "remove_member" }>,
  target: ChainMember | undefined,
): EnvironmentSet {
  const current = scopeAsEnvironmentSet(target?.scope ?? ALL_SCOPE);
  if (operation.op === "remove_member") {
    return current;
  }
  const next = scopeAsEnvironmentSet(memberScopeOf(operation.payload));
  if (operation.op === "add_member") {
    return next;
  }
  return target?.role === operation.payload.newRole
    ? symmetricDifferenceEnvironmentSets(current, next)
    : unionEnvironmentSets(current, next);
}

/**
 * 四眼の対象判定(§6.2 — propose / approve / 直接追記の拒否が共有する 1 述語):
 * 方針が有効で、op が ops に列挙されているか、常時対象(set_approval_policy 自身、
 * owner role を確立する add_member / change_role — 方針の単調性 (a))であること
 */
function isApprovalTarget(operation: ProposableOperation, policy: ApprovalPolicy | null): boolean {
  if (policy === null) {
    return false;
  }
  if (operation.op === "set_approval_policy" || establishesOwner(operation)) {
    return true;
  }
  // ops に列挙されうるのは閉集合の op のみ(構造検査済み)。列挙外の op(create /
  // rotate / checkpoint / genesis)は方針の対象になりえない
  return isApprovalTargetOp(operation.op) && policy.ops.includes(operation.op);
}

/** owner role を確立する add_member / change_role(方針の単調性 (a) の常時対象)。 */
function establishesOwner(operation: ProposableOperation): boolean {
  return (
    (operation.op === "add_member" && operation.payload.role === "owner") ||
    (operation.op === "change_role" && operation.payload.newRole === "owner")
  );
}

/**
 * 原則 2(§6.2): 提案の署名者集合 S = {owner として提案した提案者} ∪ {受理済み approve の
 * actor}。要素は (user_id, 署名時の鍵 FP) — 票は owner role で作られた署名であり、
 * admin として提案した提案者の提案署名は S に入らない(後に owner へ昇格しても同じ。
 * 昇格後は approve を追記できる — 2026-09-15 裁定 ②)
 */
function signersOf(pending: MutablePendingProposal): readonly ApprovalVote[] {
  const proposer: readonly ApprovalVote[] =
    pending.proposerRoleAtProposal === "owner"
      ? [{ userId: pending.proposerUserId, keyFingerprintHex: pending.proposerKeyFingerprintHex }]
      : [];
  return [...proposer, ...pending.approvals];
}

/**
 * 票の端末が**いま**その人の有効な端末か(§6.2「approve の票の端末語彙」— 2026-09-19 DK)。
 * 失効した端末の票・削除されたメンバーの票・別鍵で再追加された人の旧票は生きていない
 * (同じ FP を同じ人が add_device で再登録すれば復活する — 失効は単調ではない)
 */
function voteDevice(state: MutableChainState, signer: ApprovalVote): ChainDevice | undefined {
  return state.members.get(signer.userId)?.devices.get(signer.keyFingerprintHex);
}

/**
 * 原則 2(§6.2): 署名者集合 S のうち、**現時点でその FP が現 owner の有効な端末であり、
 * 端末の実効 role が owner である** distinct な user_id 数(同じ人の別端末は 1 票)。
 * 提案後に降格・削除された投票者の票は数えず、別鍵で再追加されても復活しない
 * (判定状態は「今のエントリの適用前状態」— 2026-09-15 裁定 ⑤)
 */
function countOwnerVotes(state: MutableChainState, signers: readonly ApprovalVote[]): number {
  const voters = new Set<string>();
  for (const signer of signers) {
    const member = state.members.get(signer.userId);
    const device = voteDevice(state, signer);
    if (
      member !== undefined &&
      device !== undefined &&
      effectivePermissionOf(member, device).role === "owner"
    ) {
      voters.add(signer.userId);
    }
  }
  return voters.size;
}

/**
 * 到達可能性の不変条件(§6.2 — 方針の単調性 (b)。last-owner-protected の一般化):
 * op 適用後の owner 数が、適用後の方針の required_approvals を下回る op は無効。
 * set_approval_policy(方針側が変わる)と owner を減らす remove_member / change_role
 * (owner 数側が変わる)を同じ 1 述語で判定する
 */
function quorumReachableAfter(
  operation: ProposableOperation,
  state: MutableChainState,
  target: ChainMember | undefined,
): boolean {
  const required =
    operation.op === "set_approval_policy"
      ? operation.payload.requiredApprovals
      : (state.approvalPolicy?.requiredApprovals ?? 0);
  return required === 0 || ownersCount(state) - ownersRemovedBy(operation, target) >= required;
}

/** op の適用で owner 集合から抜ける人数(owner の remove、owner からの降格 = 1)。 */
function ownersRemovedBy(operation: ProposableOperation, target: ChainMember | undefined): number {
  if (target?.role !== "owner") {
    return 0;
  }
  if (operation.op === "remove_member") {
    return 1;
  }
  return operation.op === "change_role" && operation.payload.newRole !== "owner" ? 1 : 0;
}

// ---------------------------------------------------------------------------
// role 規則(認可段の先頭 — 対象の存在に依存しない部分)

/**
 * checkpoint の role 規則(§6.2): member 以上、非空の監査ヘッドを公証できるのは
 * admin 以上のみ(監査ヘッド申告の取得自体が実効権限 admin 限定 — AUTH_SPEC §16-2)
 */
function checkpointRoleReason(
  auditHeadHashHex: string,
  actorRole: Role,
): ChainInvalidReason | null {
  if (!atLeast(actorRole, "member")) {
    return "insufficient-role";
  }
  if (auditHeadHashHex !== "" && !atLeast(actorRole, "admin")) {
    return "checkpoint-audit-role-insufficient";
  }
  return null;
}

function requireRole(actual: Role, minimum: Role): ChainInvalidReason | null {
  return atLeast(actual, minimum) ? null : "insufficient-role";
}

/** add_member の role 規則: admin 以上。admin / owner ロールの付与は owner のみ。 */
function addMemberRoleReason(grantedRole: Role, actorRole: Role): ChainInvalidReason | null {
  return requireRole(actorRole, atLeast(grantedRole, "admin") ? "owner" : "admin");
}

/**
 * op の role 規則のうち actor だけで決まる部分(§6.2 の権限列 — actor の role は
 * 署名した端末の実効 role)。対象メンバーの role に依存する部分(admin / owner を
 * 対象とする remove / change は owner のみ)は対象の解決(unknown-target)の後に
 * targetRoleReason が検査する。add_device は role 不問、revoke_device の role 規則は
 * 対象依存(自分なら不問)なので合意規則側(revokeDeviceReason)にある。網羅 Record で
 * op 追加時の規則漏れを型で防ぐ
 */
const ROLE_RULES: {
  readonly [K in ProposableOperation["op"]]: (
    operation: Extract<ProposableOperation, { op: K }>,
    actor: ActorContext,
  ) => ChainInvalidReason | null;
} = {
  genesis: () => null,
  add_member: (operation, actor) =>
    addMemberRoleReason(operation.payload.role, actor.permission.role),
  remove_member: (_operation, actor) => requireRole(actor.permission.role, "admin"),
  change_role: (_operation, actor) => requireRole(actor.permission.role, "admin"),
  create_environment: (_operation, actor) => requireRole(actor.permission.role, "member"),
  rotate_epoch: (_operation, actor) => requireRole(actor.permission.role, "member"),
  checkpoint: (operation, actor) =>
    checkpointRoleReason(operation.payload.auditHeadHashHex, actor.permission.role),
  grant_server: (_operation, actor) => requireRole(actor.permission.role, "owner"),
  revoke_server: (_operation, actor) => requireRole(actor.permission.role, "owner"),
  set_approval_policy: (_operation, actor) => requireRole(actor.permission.role, "owner"),
  add_device: () => null,
  revoke_device: () => null,
};

function roleReason(
  operation: ProposableOperation,
  actor: ActorContext,
): ChainInvalidReason | null {
  return ROLE_RULES[operation.op](operation as never, actor);
}

function targetRoleReason(
  operation: Extract<
    ProposableOperation,
    { op: "remove_member" | "change_role" | "revoke_device" }
  >,
  actor: ActorContext,
  target: ChainMember,
): ChainInvalidReason | null {
  if (atLeast(target.role, "admin") && actor.permission.role !== "owner") {
    return "insufficient-role";
  }
  if (
    operation.op === "change_role" &&
    atLeast(operation.payload.newRole, "admin") &&
    actor.permission.role !== "owner"
  ) {
    return "insufficient-role";
  }
  return null;
}

// ---------------------------------------------------------------------------
// 合意規則(role 規則・approval-required の後段。状態を変えない)

/** scope の各 environment_id の存在(§6.2 — `unknown-environment`)。 */
function scopeEnvironmentsReason(
  payload: { readonly scopeEnvironmentIds: readonly string[] },
  state: MutableChainState,
): ChainInvalidReason | null {
  for (const environmentId of payload.scopeEnvironmentIds) {
    if (!state.environments.has(environmentId)) {
      return "unknown-environment";
    }
  }
  return null;
}

/** owner を確立する add_member / change_role は scope = all のみ(§6.2 — `scope-role-mismatch`)。 */
function scopeRoleReason(role: Role, scopeKind: string): ChainInvalidReason | null {
  return role === "owner" && scopeKind !== "all" ? "scope-role-mismatch" : null;
}

/**
 * add_member / change_role 共通の scope 検査列(§6.2 — 順序固定): unknown-environment →
 * scope-role-mismatch → scope-not-contained(原則 1 — 権限変化の環境集合の包含)
 */
function memberScopeReason(
  operation: Extract<ProposableOperation, { op: "add_member" | "change_role" }>,
  establishedRole: Role,
  actor: ActorContext,
  target: ChainMember | undefined,
  state: MutableChainState,
): ChainInvalidReason | null {
  return (
    scopeEnvironmentsReason(operation.payload, state) ??
    scopeRoleReason(establishedRole, operation.payload.scopeKind) ??
    (scopeContainsEnvironmentSet(
      actor.permission.scope,
      permissionChangeEnvironments(operation, target),
    )
      ? null
      : "scope-not-contained")
  );
}

/**
 * remove_member / change_role 共通の前段(§6.2 — 順序固定): 対象の存在(`unknown-target`)→
 * 対象依存の role 規則(admin / owner が関わる変更は owner のみ)→ 最後の owner 保護
 * (owner を減らす op で現 owner が 1 名 — `last-owner-protected`)
 */
function resolveTargetedOp(
  operation: Extract<ProposableOperation, { op: "remove_member" | "change_role" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainMember | ChainInvalidReason {
  const target = state.members.get(operation.payload.targetUserId);
  if (target === undefined) {
    return "unknown-target";
  }
  const role = targetRoleReason(operation, actor, target);
  if (role !== null) {
    return role;
  }
  if (ownersRemovedBy(operation, target) === 1 && ownersCount(state) === 1) {
    return "last-owner-protected";
  }
  return target;
}

function addMemberReason(
  operation: Extract<ProposableOperation, { op: "add_member" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const p = operation.payload;
  // 検査順序(§6.2。ベクターで固定): duplicate-member → duplicate-member-key →
  // unknown-environment → scope-role-mismatch → scope-not-contained
  if (state.members.has(p.targetUserId)) {
    return "duplicate-member";
  }
  // メンバー鍵の一意性(§6.2): enc / sig のいずれかが現メンバー
  // 集合の同種鍵と一致する追加を拒否する。判定は個別鍵単位(FP 単位ではない —
  // 片鍵だけ流用したソック垢も拒否)。禁止範囲は現メンバー集合のみで、削除済み
  // メンバーの同一鍵 re-add(同一人物の復帰)は拒否しない
  if (state.memberEncPubs.has(p.encPubHex) || state.memberSigPubs.has(p.sigPubHex)) {
    return "duplicate-member-key";
  }
  return memberScopeReason(operation, p.role, actor, undefined, state);
}

function changeRoleReason(
  operation: Extract<ProposableOperation, { op: "change_role" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  // 検査順序(§6.2): unknown-target → (対象依存の role 規則)→ last-owner-protected →
  // unknown-environment → scope-role-mismatch → scope-not-contained →
  // approval-quorum-unreachable
  const target = resolveTargetedOp(operation, actor, state);
  if (typeof target === "string") {
    return target;
  }
  return (
    memberScopeReason(operation, operation.payload.newRole, actor, target, state) ??
    (quorumReachableAfter(operation, state, target) ? null : "approval-quorum-unreachable")
  );
}

function removeMemberReason(
  operation: Extract<ProposableOperation, { op: "remove_member" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  // 検査順序(§6.2): unknown-target → (対象依存の role 規則)→ last-owner-protected →
  // scope-not-contained → approval-quorum-unreachable
  const target = resolveTargetedOp(operation, actor, state);
  if (typeof target === "string") {
    return target;
  }
  if (
    !scopeContainsEnvironmentSet(
      actor.permission.scope,
      permissionChangeEnvironments(operation, target),
    )
  ) {
    return "scope-not-contained";
  }
  return quorumReachableAfter(operation, state, target) ? null : "approval-quorum-unreachable";
}

/**
 * add_device の合意規則(§6.2 — 2026-09-19 DK)。検査順序(ベクターで固定): role 規則なし →
 * duplicate-member-key(現メンバー集合の全端末鍵)→ unknown-environment → device-cap-exceeded
 * (原則 D2 — 新端末の cap ≤ 署名した端末**自身**の cap。実効権限では比べない)
 */
function addDeviceReason(
  operation: Extract<ProposableOperation, { op: "add_device" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const p = operation.payload;
  if (state.memberEncPubs.has(p.encPubHex) || state.memberSigPubs.has(p.sigPubHex)) {
    return "duplicate-member-key";
  }
  return (
    scopeEnvironmentsReason(p, state) ??
    (capWithinCap({ roleCap: p.roleCap, scope: memberScopeOf(p) }, actor.device)
      ? null
      : "device-cap-exceeded")
  );
}

/**
 * revoke_device の合意規則(§6.2 — 2026-09-19 DK)。検査順序(ベクターで固定):
 * unknown-target → unknown-device(各 FP は対象の現在有効な端末)→ 対象依存の role 規則
 * (自分なら不問・他人なら remove_member と同じ)→ last-device-protected(失効後に端末 0)→
 * scope-not-contained(他人のみ — 対象**の人**の scope ⊆ actor の実効 scope。原則 1)
 */
function revokeDeviceReason(
  operation: Extract<ProposableOperation, { op: "revoke_device" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const p = operation.payload;
  const target = state.members.get(p.targetUserId);
  if (target === undefined) {
    return "unknown-target";
  }
  if (p.deviceFingerprintsHex.some((fp) => !target.devices.has(fp))) {
    return "unknown-device";
  }
  const self = target.userId === actor.userId;
  if (!self) {
    const role =
      requireRole(actor.permission.role, "admin") ?? targetRoleReason(operation, actor, target);
    if (role !== null) {
      return role;
    }
  }
  // FP は構造段で重複無効なので、リスト長 = 失効する端末数
  if (target.devices.size - p.deviceFingerprintsHex.length < 1) {
    return "last-device-protected";
  }
  if (
    !self &&
    !scopeContainsEnvironmentSet(actor.permission.scope, scopeAsEnvironmentSet(target.scope))
  ) {
    return "scope-not-contained";
  }
  return null;
}

async function grantServerReason(
  operation: Extract<ProposableOperation, { op: "grant_server" }>,
  state: MutableChainState,
): Promise<ChainInvalidReason | null> {
  const p = operation.payload;
  // 認可段の検査順序(§6.2。ベクターで固定): role 規則 →
  // 再 grant 規則(§6.3)→ サーバー鍵の重複。FP 整合は payload 自体の
  // 自己整合(§9)であり role の直後に検査する(従来位置を維持)。
  // サーバー鍵 FP = SHA-256(server_enc_pub)[:16](enc 鍵のみ。§9 / ベクター定義)
  const encPub = decodeHex(p.serverEncPubHex) ?? new Uint8Array(0);
  const digest = await sha256(encPub);
  if (encodeHex(digest.slice(0, FINGERPRINT_BYTES)) !== p.serverKeyFingerprintHex) {
    return "invalid-payload";
  }
  // 同一サーバー鍵への再 grant の二層判定(所有者裁定):
  // 開示スコープはスコープ拡大(旧 ⊆ 新)のみ受理する。縮小を許すと revoke_server +
  // rotate_epoch(§7 の全環境ローテーション義務)を迂回して「開示を止めたつもり」に
  // なれてしまうため、縮小は必ず失効経路を通す。拡大は未開示環境を足すだけなので無害。
  // 一方 lease_policy は自由改訂(縮小・全削除を含む): ポリシーはリース経路(§9.1)の
  // ACL であり、サーバーの既知 DEK 集合を変えない(§6.3 — 判定はフィールドごとに独立)
  const existing = state.serverGrants.get(p.serverKeyFingerprintHex);
  if (existing !== undefined) {
    const newScope = new Set(p.scopeEnvironmentIds);
    if (existing.scopeEnvironmentIds.some((id) => !newScope.has(id))) {
      return "grant-scope-narrowed";
    }
  }
  // サーバー鍵の一意性(§6.2): サーバー enc 公開鍵が現メンバーの
  // enc 公開鍵と一致する grant は拒否する(「鍵 → 主体」逆引きの一意性の
  // 受信者クラス横断版)。逆方向(有効 grant のサーバー鍵を add_member に流用)は
  // 仕様の明示的な対象外のまま(§6.2 メンバー鍵一意性の「注意」)
  return state.memberEncPubs.has(p.serverEncPubHex) ? "duplicate-server-key" : null;
}

function createEnvironmentReason(
  operation: Extract<ProposableOperation, { op: "create_environment" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  // 検査順序(§6.2): duplicate-environment → environment-out-of-scope。
  // environment_id はチェーン履歴全体で一意。チェーンは環境の削除を
  // 観測しない(削除はデータプレーン操作)ため、environments マップは削除されず、
  // 削除済み環境 ID の再作成もここで拒否される(ID 再利用禁止の合意規則昇格)。
  // 新 environment_id は listed の scope に含まれえない(未存在環境への事前スコープは
  // 無い)ため、環境の作成は scope = all の actor のみができる — 同じ 1 述語で判定する
  if (state.environments.has(operation.payload.environmentId)) {
    return "duplicate-environment";
  }
  return scopeIncludesEnvironment(actor.permission.scope, operation.payload.environmentId)
    ? null
    : "environment-out-of-scope";
}

function rotateEpochReason(
  operation: Extract<ProposableOperation, { op: "rotate_epoch" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const p = operation.payload;
  // 検査順序(§6.2。ベクターで固定): unknown-environment → environment-out-of-scope →
  // エポック順序。当該 environment_id の create_environment が先行していなければ
  // 無効(「未観測なら初期値 1」の既定値フォールバックは持たない)
  const environment = state.environments.get(p.environmentId);
  if (environment === undefined) {
    return "unknown-environment";
  }
  if (!scopeIncludesEnvironment(actor.permission.scope, p.environmentId)) {
    return "environment-out-of-scope";
  }
  // エポックは環境ごとのカウンタで必ず +1(所有者裁定・案 3)。
  // 巻き戻し(削除済みメンバーが保持する旧 DEK で新しい値が暗号化される)、
  // 重複、ジャンプ(member 権限の 1 署名で safe integer 上限まで飛ばして
  // 以後のローテーションを不能にする DoS)をすべて拒否する
  return p.newEpoch === environment.currentEpoch + 1 ? null : "epoch-out-of-sequence";
}

/**
 * checkpoint の合意規則(§6.2)。検査順序(ベクターで固定): unknown-environment →
 * environment-out-of-scope → checkpoint-epoch-mismatch → checkpoint-regression。
 * 複数環境エントリ間は**検査段ごとに全エントリを走査**する(stage-wise —
 * session-33 裁定 C。authz-checkpoint-unknown-precedes-epoch が固定)。
 * エポックは「エントリ時点(自エントリ適用前)」の現エポックとの厳密一致 —
 * checkpoint 自身はエポックを動かさないため、境界チェックポイント(複合の
 * H+2 — AUTH_SPEC §12-4)でも同梱エントリ(H+1)適用後の状態と自然に一致する。
 * タプル内容(マニフェスト・値・監査ヘッド)はここでは検証不能(§6.2 の
 * 「形式は合意規則、内容は照合側」— サーバー §6.4 / クライアント §6.3)。
 */
function checkpointReason(
  environments: readonly CheckpointEnvironmentEntry[],
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const stage = (
    rejected: (tuple: CheckpointEnvironmentEntry) => boolean,
    reason: ChainInvalidReason,
  ): ChainInvalidReason | null => (environments.some(rejected) ? reason : null);
  return (
    stage((tuple) => !state.environments.has(tuple.environmentId), "unknown-environment") ??
    stage(
      (tuple) => !scopeIncludesEnvironment(actor.permission.scope, tuple.environmentId),
      "environment-out-of-scope",
    ) ??
    stage(
      (tuple) => state.environments.get(tuple.environmentId)?.currentEpoch !== tuple.epoch,
      "checkpoint-epoch-mismatch",
    ) ??
    // 非後退は等号を許す(rotate 境界分の後、再暗号化完了後の周期 checkpoint が
    // 同一 manifest_version を新しい values_digest で正当に再公証する — §6.3)
    stage((tuple) => {
      const prior = state.checkpoints.get(tuple.environmentId);
      return prior !== undefined && tuple.manifestVersion < prior.manifestVersion;
    }, "checkpoint-regression")
  );
}

// op ごとの合意規則(role 規則と approval-required の後段 — §6.2 の各 op の検査列の
// 残り)。直接追記・propose(内側 op の事前検査)・approve(適用時の再検査)が
// 共有する。状態は変えない(適用は applyOperation)。網羅 Record で op 追加時の
// 規則漏れを型で防ぐ
const CONSENSUS_RULES: {
  readonly [K in ProposableOperation["op"]]: (
    operation: Extract<ProposableOperation, { op: K }>,
    actor: ActorContext,
    state: MutableChainState,
  ) => ChainInvalidReason | null | Promise<ChainInvalidReason | null>;
} = {
  // genesis は seq 1 の直接追記のみ(フレーミングが固定)。内側 op としては
  // 方針の対象になりえず approval-not-required で先に落ちるため到達しない
  genesis: () => null,
  add_member: addMemberReason,
  change_role: changeRoleReason,
  remove_member: removeMemberReason,
  grant_server: (operation, _actor, state) => grantServerReason(operation, state),
  revoke_server: (operation, _actor, state) =>
    state.serverGrants.has(operation.payload.serverKeyFingerprintHex)
      ? null
      : "unknown-server-grant",
  create_environment: createEnvironmentReason,
  rotate_epoch: rotateEpochReason,
  checkpoint: (operation, actor, state) =>
    checkpointReason(operation.payload.environments, actor, state),
  set_approval_policy: (operation, _actor, state) =>
    quorumReachableAfter(operation, state, undefined) ? null : "approval-quorum-unreachable",
  add_device: addDeviceReason,
  revoke_device: revokeDeviceReason,
};

async function consensusReason(
  operation: ProposableOperation,
  actor: ActorContext,
  state: MutableChainState,
): Promise<ChainInvalidReason | null> {
  return CONSENSUS_RULES[operation.op](operation as never, actor, state);
}

// ---------------------------------------------------------------------------
// 状態遷移(合意規則を通過した op の適用)

// 環境の初期エポック(create_environment 直後の値 — CRYPTO_SPEC §3 / §6.2)
const INITIAL_EPOCH = 1;

function applyGenesis(
  entry: ChainEntry & { readonly op: "genesis" },
  state: MutableChainState,
): void {
  // genesis の鍵 = 最初の端末(cap は構造的に (owner, all)。FP は resolveActorSigPub で照合済み)
  const device = firstDeviceOf(entry.payload, entry.actor.keyFingerprintHex, entry.seq);
  state.members.set(entry.actor.userId, {
    userId: entry.actor.userId,
    role: "owner",
    // 作成者の scope は構造的に all(§6.2 — genesis は payload に scope を持たない)
    scope: ALL_SCOPE,
    devices: new Map([[device.keyFingerprintHex, device]]),
  });
  // genesis 時点のメンバー集合は空なので鍵重複は構造上生じない(§6.2)。
  // 以後の add_member / add_device の比較対象として owner の鍵も索引に載せる
  indexDeviceKeys(state, device);
}

async function applyAddMember(
  operation: Extract<ProposableOperation, { op: "add_member" }>,
  state: MutableChainState,
  seq: number,
): Promise<void> {
  const p = operation.payload;
  const device = firstDeviceOf(p, await userFingerprintHex(p.encPubHex, p.sigPubHex), seq);
  state.members.set(p.targetUserId, {
    userId: p.targetUserId,
    role: p.role,
    scope: memberScopeOf(p),
    devices: new Map([[device.keyFingerprintHex, device]]),
  });
  indexDeviceKeys(state, device);
}

/** add_device: actor 自身の端末集合へ新端末を加える(対象 = actor — §6.2)。 */
async function applyAddDevice(
  operation: Extract<ProposableOperation, { op: "add_device" }>,
  state: MutableChainState,
  seq: number,
  actorUserId: string,
): Promise<void> {
  const p = operation.payload;
  const member = state.members.get(actorUserId);
  if (member === undefined) {
    return;
  }
  const device: ChainDevice = {
    keyFingerprintHex: await userFingerprintHex(p.encPubHex, p.sigPubHex),
    encPubHex: p.encPubHex,
    sigPubHex: p.sigPubHex,
    roleCap: p.roleCap,
    scope: memberScopeOf(p),
    addedSeq: seq,
  };
  state.members.set(member.userId, {
    ...member,
    devices: new Map([...member.devices, [device.keyFingerprintHex, device]]),
  });
  indexDeviceKeys(state, device);
}

/** revoke_device: 対象の端末集合から列挙された端末を外す(鍵索引からも外す)。 */
function applyRevokeDevice(
  operation: Extract<ProposableOperation, { op: "revoke_device" }>,
  state: MutableChainState,
): void {
  const p = operation.payload;
  const target = state.members.get(p.targetUserId);
  if (target === undefined) {
    return;
  }
  const devices = new Map(target.devices);
  for (const fp of p.deviceFingerprintsHex) {
    const device = devices.get(fp);
    if (device !== undefined) {
      devices.delete(fp);
      unindexDeviceKeys(state, device);
    }
  }
  state.members.set(target.userId, { ...target, devices });
}

function applyChangeRole(
  operation: Extract<ProposableOperation, { op: "change_role" }>,
  state: MutableChainState,
): void {
  const p = operation.payload;
  const target = state.members.get(p.targetUserId);
  if (target !== undefined) {
    // 新 (role, scope) の全置換(§6.2)
    state.members.set(target.userId, { ...target, role: p.newRole, scope: memberScopeOf(p) });
  }
}

function applyRemoveMember(
  operation: Extract<ProposableOperation, { op: "remove_member" }>,
  state: MutableChainState,
): void {
  const target = state.members.get(operation.payload.targetUserId);
  if (target !== undefined) {
    state.members.delete(target.userId);
    // remove_member は対象の全端末を同時に終える(§6.2)
    for (const device of target.devices.values()) {
      unindexDeviceKeys(state, device);
    }
  }
}

function applyGrantServer(
  operation: Extract<ProposableOperation, { op: "grant_server" }>,
  state: MutableChainState,
  seq: number,
): void {
  const p = operation.payload;
  state.serverGrants.set(p.serverKeyFingerprintHex, {
    serverKeyFingerprintHex: p.serverKeyFingerprintHex,
    serverEncPubHex: p.serverEncPubHex,
    // 再 grant では有効 grant を確立したエントリが置き換わるため seq も前進する
    // (AUDIT_SPEC §3.5 の grant_chain_seq の出所 — chain-entries.json の
    // valid_appends `regrant-lease-policy-revised` が 9 → 10 の前進を固定する)
    grantSeq: seq,
    scopeEnvironmentIds: [...p.scopeEnvironmentIds],
    leasePolicy: p.leasePolicy.map((element) => ({
      issuerUrl: element.issuerUrl,
      audience: element.audience,
      claimConstraints: element.claimConstraints.map((constraint) => ({ ...constraint })),
    })),
  });
}

function applyCreateEnvironment(
  operation: Extract<ProposableOperation, { op: "create_environment" }>,
  state: MutableChainState,
  seq: number,
): void {
  state.environments.set(operation.payload.environmentId, {
    currentEpoch: INITIAL_EPOCH,
    createdAtSeq: seq,
    epochStartSeqs: new Map([[INITIAL_EPOCH, seq]]),
    dekCommitments: new Map([[INITIAL_EPOCH, operation.payload.dekCommitmentHex]]),
  });
}

function applyRotateEpoch(
  operation: Extract<ProposableOperation, { op: "rotate_epoch" }>,
  state: MutableChainState,
  seq: number,
): void {
  const p = operation.payload;
  const environment = state.environments.get(p.environmentId);
  if (environment !== undefined) {
    environment.currentEpoch = p.newEpoch;
    environment.epochStartSeqs.set(p.newEpoch, seq);
    environment.dekCommitments.set(p.newEpoch, p.dekCommitmentHex);
  }
}

function applyCheckpoint(
  operation: Extract<ProposableOperation, { op: "checkpoint" }>,
  state: MutableChainState,
  seq: number,
): void {
  for (const tuple of operation.payload.environments) {
    state.checkpoints.set(tuple.environmentId, {
      seq,
      epoch: tuple.epoch,
      manifestVersion: tuple.manifestVersion,
      manifestSigHashHex: tuple.manifestSigHashHex,
      valuesDigestHex: tuple.valuesDigestHex,
    });
  }
}

function applySetApprovalPolicy(
  operation: Extract<ProposableOperation, { op: "set_approval_policy" }>,
  state: MutableChainState,
): void {
  const p = operation.payload;
  // required_approvals = 0 はオフ(§6.2 — 方針が一度も確立されていない状態と同じ)。
  // ops は集合(重複は構造段で拒否しない — grant_server の scope と同じ)なので去重して保持する
  state.approvalPolicy =
    p.requiredApprovals === 0
      ? null
      : { ops: [...new Set(p.ops)], requiredApprovals: p.requiredApprovals };
}

// op ごとの状態遷移(合意規則を通過した op の適用)。網羅 Record で op 追加時の
// 適用漏れを型で防ぐ。seq は適用エントリの seq(提案経由なら定足数に達した
// approve エントリの seq — inclusive 規約)。actorUserId は帰属主体(add_device の
// 対象 = actor 自身)
const OPERATION_APPLIERS: {
  readonly [K in ProposableOperation["op"]]: (
    operation: Extract<ProposableOperation, { op: K }>,
    state: MutableChainState,
    seq: number,
    actorUserId: string,
  ) => void | Promise<void>;
} = {
  // 直接追記の genesis は applyGenesis(actor を要する)。内側 op としては到達しない
  genesis: () => undefined,
  add_member: applyAddMember,
  change_role: applyChangeRole,
  remove_member: applyRemoveMember,
  grant_server: applyGrantServer,
  revoke_server: (operation, state) => {
    state.serverGrants.delete(operation.payload.serverKeyFingerprintHex);
  },
  create_environment: applyCreateEnvironment,
  rotate_epoch: applyRotateEpoch,
  checkpoint: applyCheckpoint,
  set_approval_policy: applySetApprovalPolicy,
  add_device: applyAddDevice,
  revoke_device: applyRevokeDevice,
};

/** 合意規則を通過した op を状態へ適用する。 */
async function applyOperation(
  operation: ProposableOperation,
  state: MutableChainState,
  seq: number,
  actorUserId: string,
): Promise<void> {
  await OPERATION_APPLIERS[operation.op](operation as never, state, seq, actorUserId);
}

// ---------------------------------------------------------------------------
// エントリの評価(直接追記 / propose / approve / withdraw)

/**
 * 直接追記(§6.2): role 規則 → approval-required(方針の対象は S = {actor} で
 * 定足数に届かない — 原則 2 の導出)→ 合意規則 → 適用
 */
async function evaluateDirect(
  operation: ProposableOperation,
  actor: ActorContext,
  state: MutableChainState,
  seq: number,
): Promise<ChainInvalidReason | AppliedOperation> {
  const role = roleReason(operation, actor);
  if (role !== null) {
    return role;
  }
  if (isApprovalTarget(operation, state.approvalPolicy)) {
    return "approval-required";
  }
  const reason = await consensusReason(operation, actor, state);
  if (reason !== null) {
    return reason;
  }
  await applyOperation(operation, state, seq, actor.userId);
  return { operation, actorUserId: actor.userId };
}

/**
 * propose(§6.2): role 規則(内側 op の規則)→ approval-not-required(方針オフ /
 * 対象外の op)→ 内側 op の合意規則(approval-required を除く — S を集めている最中)。
 * 通過した提案は pending に載る(識別子 = 提案エントリの entry_hash)
 */
async function evaluatePropose(
  entry: ChainEntry & { readonly op: "propose" },
  entryHashHex: string,
  actor: ActorContext,
  state: MutableChainState,
): Promise<ChainInvalidReason | null> {
  const inner = entry.payload.inner;
  const role = roleReason(inner, actor);
  if (role !== null) {
    return role;
  }
  if (!isApprovalTarget(inner, state.approvalPolicy)) {
    return "approval-not-required";
  }
  const reason = await consensusReason(inner, actor, state);
  if (reason !== null) {
    return reason;
  }
  state.pendingProposals.set(entryHashHex, {
    proposalSeq: entry.seq,
    proposalHashHex: entryHashHex,
    proposerUserId: actor.userId,
    proposerKeyFingerprintHex: actor.device.keyFingerprintHex,
    proposerRoleAtProposal: actor.permission.role,
    inner,
    expiresAtMs: entry.payload.expiresAtMs,
    approvals: [],
  });
  return null;
}

/**
 * approve(§6.2): role 規則(owner)→ unknown-proposal → duplicate-approval(actor が
 * 既に S の要素)→ approval-not-required(現方針で対象外)→ proposal-expired →
 * 票数 = |S ∩ 現 owners|(原則 2)が required に達したら proposal-void(提案者の在籍・
 * 鍵 FP・内側 op の role)→ 内側 op の合意規則(適用時点の状態)→ 適用(actor =
 * 提案者、seq = この approve)。届かなければ投票を記録して終える
 */
async function evaluateApprove(
  entry: ChainEntry & { readonly op: "approve" },
  actor: ActorContext,
  state: MutableChainState,
): Promise<ChainInvalidReason | AppliedOperation | null> {
  if (actor.permission.role !== "owner") {
    return "insufficient-role";
  }
  const pending = state.pendingProposals.get(entry.payload.proposalHashHex);
  if (pending === undefined) {
    return "unknown-proposal";
  }
  const reason = approveVoteReason(entry, actor, pending, state);
  if (reason !== null) {
    return reason;
  }
  // S ∪ {この actor の (user_id, 現在の鍵 FP)}(原則 2)。方針は approveVoteReason が
  // 有効(非 null)を確認済み — 万一 null なら定足数に届かない側へ倒す
  const signature: ApprovalVote = {
    userId: actor.userId,
    keyFingerprintHex: actor.device.keyFingerprintHex,
  };
  const required = state.approvalPolicy?.requiredApprovals ?? Number.POSITIVE_INFINITY;
  if (countOwnerVotes(state, [...signersOf(pending), signature]) < required) {
    pending.approvals.push(signature);
    return null;
  }
  return completeProposal(pending, state, entry.seq);
}

/**
 * approve の投票前検査(§6.2 の順序): duplicate-approval(actor の user_id が S に**生きた**
 * 票を持つ — 票の端末がいまその人の有効な端末である。owner の提案は 1 票 = 自己承認は重複。
 * 同じ人の別端末の再投票も重複〔distinct は user_id — 2026-09-19 DK〕。失効した端末の票・
 * 別鍵で再追加された投票者の旧票は生きていないので改めて投票できる)→
 * approval-not-required(現方針で対象外 — 方針オフを含む)→ proposal-expired
 * (timestamp_ms > expires_at_ms — 本仕様で timestamp を合意規則に用いる唯一の箇所)
 */
function approveVoteReason(
  entry: ChainEntry & { readonly op: "approve" },
  actor: ActorContext,
  pending: MutablePendingProposal,
  state: MutableChainState,
): ChainInvalidReason | null {
  const live = signersOf(pending).some(
    (signer) => signer.userId === actor.userId && voteDevice(state, signer) !== undefined,
  );
  if (live) {
    return "duplicate-approval";
  }
  if (!isApprovalTarget(pending.inner, state.approvalPolicy)) {
    return "approval-not-required";
  }
  return entry.timestampMs > pending.expiresAtMs ? "proposal-expired" : null;
}

/**
 * 定足数到達時の適用(§6.2): 適用時点の状態で提案者(在籍・提案した端末がいま有効・
 * 内側 op の role〔提案した端末の実効 role〕— `proposal-void`)と内側 op の合意規則を
 * 再検査し、通れば提案者を actor として適用する。失敗した approve は無効エントリであり、
 * 提案は pending のまま残る(withdraw で閉じる)
 */
async function completeProposal(
  pending: MutablePendingProposal,
  state: MutableChainState,
  seq: number,
): Promise<ChainInvalidReason | AppliedOperation> {
  const proposer = state.members.get(pending.proposerUserId);
  const device = proposer?.devices.get(pending.proposerKeyFingerprintHex);
  if (proposer === undefined || device === undefined) {
    return "proposal-void";
  }
  const actor = actorContextOf(proposer, device);
  if (roleReason(pending.inner, actor) !== null) {
    return "proposal-void";
  }
  const reason = await consensusReason(pending.inner, actor, state);
  if (reason !== null) {
    return reason;
  }
  await applyOperation(pending.inner, state, seq, proposer.userId);
  state.pendingProposals.delete(pending.proposalHashHex);
  // 適用した内側 op の actor は提案者として扱う(在籍・帰属の記録)
  return { operation: pending.inner, actorUserId: proposer.userId };
}

function evaluateWithdraw(
  entry: ChainEntry & { readonly op: "withdraw" },
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const pending = state.pendingProposals.get(entry.payload.proposalHashHex);
  // 非 owner は「参照先の pending 提案の提案者」である場合にのみ role を満たす
  // (未知の提案の提案者にはなりえないため role 規則が先に落ちる — ベクター固定)
  if (actor.permission.role !== "owner" && pending?.proposerUserId !== actor.userId) {
    return "insufficient-role";
  }
  if (pending === undefined) {
    return "unknown-proposal";
  }
  state.pendingProposals.delete(pending.proposalHashHex);
  return null;
}

/**
 * 認可 + 状態遷移(検証段 5)。返り値: 拒否理由、または適用された op(履歴索引へ
 * 記録する — propose / withdraw / 定足数未達の approve は状態遷移を伴わず null)
 */
async function evaluateEntry(
  entry: ChainEntry,
  entryHashHex: string,
  state: MutableChainState,
): Promise<ChainInvalidReason | AppliedOperation | null> {
  if (entry.op === "genesis") {
    applyGenesis(entry, state);
    return { operation: entry, actorUserId: entry.actor.userId };
  }
  // actor は resolveActorSigPub で存在・端末を確認済み
  const member = state.members.get(entry.actor.userId);
  if (member === undefined) {
    return "actor-not-member";
  }
  const device = member.devices.get(entry.actor.keyFingerprintHex);
  if (device === undefined) {
    return "actor-key-mismatch";
  }
  const actor = actorContextOf(member, device);
  switch (entry.op) {
    case "propose":
      return evaluatePropose(entry, entryHashHex, actor, state);
    case "approve":
      return evaluateApprove(entry, actor, state);
    case "withdraw":
      return evaluateWithdraw(entry, actor, state);
    default:
      return evaluateDirect(entry, actor, state, entry.seq);
  }
}

// ---------------------------------------------------------------------------
// 履歴索引への記録

/** 適用済み状態から対象メンバーの最初の端末(在籍開始時は端末 1 つ)を引いて tenure 開始を記録する。 */
function recordTenureStartOf(
  history: ChainHistoryBuilder,
  state: MutableChainState,
  userId: string,
  seq: number,
): void {
  const member = state.members.get(userId);
  const device = member === undefined ? undefined : soleDeviceOf(member);
  if (member !== undefined && device !== undefined) {
    history.recordTenureStart(userId, seq, device, member.role, member.scope);
  }
}

/** 適用済み状態から add_device で載った端末(enc 公開鍵で同定)を引いて記録する。 */
function recordDeviceAddedOf(
  history: ChainHistoryBuilder,
  state: MutableChainState,
  actorUserId: string,
  encPubHex: string,
): void {
  for (const device of state.members.get(actorUserId)?.devices.values() ?? []) {
    if (device.encPubHex === encPubHex) {
      history.recordDeviceAdded(actorUserId, device);
      return;
    }
  }
}

// op ごとの履歴記録(網羅 Record — op 追加時の記録漏れを型で防ぐ)。tenure の
// 開始・終了・(role, scope) 変更はすべて適用エントリ自身の seq を境界にする
// (§6.3 の inclusive 規約 — value-signature.json のベクターが固定。提案経由の
// 適用は定足数に達した approve エントリの seq)。grant_server / revoke_server /
// set_approval_policy は履歴索引に載せる状態を持たない
const HISTORY_RECORDERS: {
  readonly [K in ProposableOperation["op"]]: (
    history: ChainHistoryBuilder,
    operation: Extract<ProposableOperation, { op: K }>,
    seq: number,
    state: MutableChainState,
    actorUserId: string,
  ) => void;
} = {
  genesis: (history: ChainHistoryBuilder, _operation, seq, state, actorUserId) =>
    recordTenureStartOf(history, state, actorUserId, seq),
  add_member: (history: ChainHistoryBuilder, operation, seq, state) =>
    recordTenureStartOf(history, state, operation.payload.targetUserId, seq),
  change_role: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordRoleChange(
      operation.payload.targetUserId,
      seq,
      operation.payload.newRole,
      memberScopeOf(operation.payload),
    ),
  remove_member: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordTenureEnd(operation.payload.targetUserId, seq),
  create_environment: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordEnvironmentCreated(operation.payload.environmentId, seq),
  rotate_epoch: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordEpochRotated(operation.payload.environmentId, operation.payload.newEpoch, seq),
  checkpoint: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordCheckpoint(seq, operation.payload.environments),
  grant_server: () => undefined,
  revoke_server: () => undefined,
  set_approval_policy: () => undefined,
  add_device: (history: ChainHistoryBuilder, operation, _seq, state, actorUserId) =>
    recordDeviceAddedOf(history, state, actorUserId, operation.payload.encPubHex),
  revoke_device: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordDevicesRevoked(
      operation.payload.targetUserId,
      seq,
      operation.payload.deviceFingerprintsHex,
    ),
};

function recordHistory(
  history: ChainHistoryBuilder,
  applied: AppliedOperation,
  seq: number,
  state: MutableChainState,
): void {
  HISTORY_RECORDERS[applied.operation.op](
    history,
    applied.operation as never,
    seq,
    state,
    applied.actorUserId,
  );
}

/**
 * 適用前の 1 エントリ検査(検証段順: フレーミング → payload 構造 → actor 解決 →
 * 署名)。null = 通過。認可 + 状態遷移は evaluateEntry が続けて検査する。
 */
async function checkEntryBeforeApply(
  entry: ChainEntry,
  seq: number,
  prevHash: string,
  state: MutableChainState,
): Promise<ChainInvalidReason | null> {
  // 配列スロット自体が null / 非オブジェクトの細工データでも throw しない
  if (!isRecord(entry)) {
    return "invalid-payload";
  }
  const framing = checkFraming(entry, seq, prevHash);
  if (framing !== null) {
    return framing;
  }
  const shape = checkPayloadShape(entry);
  if (shape !== null) {
    return shape;
  }
  const actor = await resolveActorSigPub(entry, state);
  if ("reason" in actor) {
    return actor.reason;
  }
  if (!(await verifyEntrySignature(entry, actor.sigPubHex))) {
    return "bad-signature";
  }
  return null;
}

function freezePendingProposals(
  pending: ReadonlyMap<string, MutablePendingProposal>,
): ReadonlyMap<string, PendingProposal> {
  const frozen = new Map<string, PendingProposal>();
  for (const [hash, proposal] of pending) {
    frozen.set(hash, { ...proposal, approvals: proposal.approvals.map((vote) => ({ ...vote })) });
  }
  return frozen;
}

async function verifyChainCore(
  entries: readonly ChainEntry[],
  history: ChainHistoryBuilder | null,
): Promise<CryptoResult<ChainState>> {
  if (entries.length === 0) {
    return { ok: false, error: { kind: "ChainInvalid", seq: 0, reason: "empty-chain" } };
  }
  const state: MutableChainState = {
    members: new Map(),
    serverGrants: new Map(),
    environments: new Map(),
    checkpoints: new Map(),
    memberEncPubs: new Set(),
    memberSigPubs: new Set(),
    approvalPolicy: null,
    pendingProposals: new Map(),
  };
  let prevHash = GENESIS_PREV_HASH;
  let seq = 0;
  const fail = (reason: ChainInvalidReason) =>
    ({ ok: false, error: { kind: "ChainInvalid", seq, reason } }) as const;

  for (const [index, entry] of entries.entries()) {
    seq = index + 1;
    const rejected = await checkEntryBeforeApply(entry, seq, prevHash, state);
    if (rejected !== null) {
      return fail(rejected);
    }
    // entry_hash は署名検証で同一フィールドの正規化が成功した後にのみ計算する。
    // propose の識別子(§6.2)として適用前に要るため、ここで求める
    const entryHashHex = await computeChainEntryHash(entry);
    const evaluated = await evaluateEntry(entry, entryHashHex, state);
    if (typeof evaluated === "string") {
      return fail(evaluated);
    }
    if (history !== null && evaluated !== null) {
      recordHistory(history, evaluated, seq, state);
    }
    prevHash = entryHashHex;
    history?.recordEntryHash(prevHash);
  }

  return {
    ok: true,
    value: {
      members: state.members,
      serverGrants: state.serverGrants,
      environments: state.environments,
      checkpoints: state.checkpoints,
      approvalPolicy: state.approvalPolicy,
      pendingProposals: freezePendingProposals(state.pendingProposals),
      headSeq: entries.length,
      headHashHex: prevHash,
    },
  };
}

/**
 * Verifies a full membership chain (CRYPTO_SPEC §6.3): framing, payload
 * shape, actor identity, Ed25519 signatures and the §6.2 role / scope /
 * four-eyes rules — and derives the resulting state (current members with
 * roles and scopes, active server grants, observed environment epochs, the
 * approval policy and pending proposals, chain head).
 *
 * Verification is fail-fast: the returned error carries the failing entry's
 * `seq` and a machine-readable reason.
 *
 * Entries are treated as untrusted input (chains are distributed by the
 * server): every field is re-validated at runtime regardless of the static
 * types, so malformed data yields `invalid-payload` instead of throwing.
 */
export async function verifyChain(
  entries: readonly ChainEntry[],
): Promise<CryptoResult<ChainState>> {
  return verifyChainCore(entries, null);
}

/**
 * `verifyChain` plus the per-snapshot history index (CRYPTO_SPEC §6.3 /
 * §4.1 — the input of the declared-head-time value verification). The index
 * is built inside the same verification loop, so it can only exist for a
 * chain that passed full verification, and per-value checks never re-verify
 * chain signatures (session-14 裁定 A).
 */
export async function verifyChainWithHistory(
  entries: readonly ChainEntry[],
): Promise<CryptoResult<{ readonly state: ChainState; readonly history: ChainHistoryIndex }>> {
  const builder = new ChainHistoryBuilder();
  const result = await verifyChainCore(entries, builder);
  if (!result.ok) {
    return result;
  }
  return { ok: true, value: { state: result.value, history: builder.build() } };
}
