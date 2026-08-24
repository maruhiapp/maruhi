// CRYPTO_SPEC §6.3: クライアント検証 — prev_hash 連続性、Ed25519 署名、
// §6.2 の role 権限規則を全エントリで検証し、検証済みチェーンから
// 現メンバー集合(role 付き)・有効 grant_server 集合・観測エポックを導出する。
//
// 検証順序(認可系テストベクターの expected_reason と対応):
//   1. フレーミング(suite / seq / genesis 位置 / prev_hash)
//   2. payload の構造検証(hex 長・role 値・数値範囲)→ invalid-payload
//   3. actor 解決(現メンバーか / 申告 FP が登録鍵と一致するか)
//      → actor-not-member / actor-key-mismatch
//   4. 署名検証(actor の登録 sig 公開鍵)→ bad-signature
//   5. 認可 + 状態遷移(role 規則・対象の存在・最後の owner 保護)

import { concatBytes, decodeHex, encodeHex, utf8Encode } from "./bytes.ts";
import { canonicalChainSignedBytes, computeChainEntryHash } from "./chain-canonical.ts";
import { ChainHistoryBuilder, type ChainHistoryIndex } from "./chain-history.ts";
import type { ChainEntry, ChainMember, ChainState, Role, ServerGrant } from "./chain-types.ts";
import type { ChainInvalidReason, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { SUITE_ID } from "./suite.ts";

const GENESIS_PREV_HASH = "0".repeat(64);
const ROLE_RANK: Readonly<Record<Role, number>> = { reader: 0, member: 1, admin: 2, owner: 3 };
const ROLES: readonly Role[] = ["owner", "admin", "member", "reader"];
const FINGERPRINT_BYTES = 16;
const SIGNATURE_BYTES = 64;
const SHA256_BYTES = 32;
// フィールドサイズ上限(CRYPTO_SPEC §6.1。2026-08-02 決定): チェーン有効性の
// 合意規則。巨大 payload による検証クライアントの資源消費(可用性)対策
const MAX_FIELD_BYTES = 1024;
const MAX_SCOPE_ENVIRONMENTS = 256;
// lease_policy の上限(CRYPTO_SPEC §6.2。2026-08-12): 要素 8・要素あたり claim
// 制約 8(各文字列は MAX_FIELD_BYTES)。仕様適合 grant_server エントリの正規化
// サイズが §6.4 の受理ポリシー上限を数学的に下回り続けるように選ばれた合意規則
const MAX_LEASE_POLICY_ISSUERS = 8;
const MAX_LEASE_CLAIM_CONSTRAINTS = 8;

interface MutableEnvironmentState {
  currentEpoch: number;
  readonly createdAtSeq: number;
  readonly epochStartSeqs: Map<number, number>;
  readonly dekCommitments: Map<number, string>;
}

interface MutableChainState {
  readonly members: Map<string, ChainMember>;
  readonly serverGrants: Map<string, ServerGrant>;
  // 環境集合(§6.2 create_environment の導出)。チェーンは環境の削除を観測しない
  // (削除はデータプレーン操作)ため、このマップ自体が「履歴全体の使用済み ID」
  // でもあり、duplicate-environment の判定に追加の索引を要しない
  readonly environments: Map<string, MutableEnvironmentState>;
  // 現メンバー集合の enc / sig 公開鍵の索引(メンバー鍵の一意性 — §6.2)。
  // 本規則自体が「各鍵は高々 1 メンバーに属する」を不変条件にするため、
  // remove_member での Set 削除は他メンバーの鍵を消さない(健全)。
  // hex は §6.1 の形状検証(decodeHex = 小文字のみ)を通った正規形なので
  // 文字列一致 = バイト一致
  readonly memberEncPubs: Set<string>;
  readonly memberSigPubs: Set<string>;
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
  if (!isRecord(entry.payload)) {
    return "invalid-payload";
  }
  return operationShapeOk(entry) ? null : "invalid-payload";
}

function shapeGenesis(p: { encPubHex: unknown; sigPubHex: unknown }): boolean {
  return isHexOfLength(p.encPubHex, 32) && isHexOfLength(p.sigPubHex, 32);
}

function shapeAddMember(p: {
  targetUserId: unknown;
  encPubHex: unknown;
  sigPubHex: unknown;
  role: unknown;
}): boolean {
  return isBoundedId(p.targetUserId) && shapeGenesis(p) && isRole(p.role);
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
    // lease_policy(§6.2。2026-08-12): 構造のみ合意規則(評価意味論は AUTH_SPEC §14)。
    // 旧 3 フィールド形式(leasePolicy 欠落)はここで invalid-payload になる
    Array.isArray(p.leasePolicy) &&
    p.leasePolicy.length <= MAX_LEASE_POLICY_ISSUERS &&
    p.leasePolicy.every((element) => shapeLeasePolicyIssuer(element))
  );
}

// op ごとの payload 形状述語(§6.1 / §6.2 の構造検査)。分岐でなく表引きにして
// op 追加時の検査漏れを型(網羅 Record)で防ぐ
const PAYLOAD_SHAPES: {
  readonly [K in ChainEntry["op"]]: (payload: Extract<ChainEntry, { op: K }>["payload"]) => boolean;
} = {
  genesis: shapeGenesis,
  add_member: shapeAddMember,
  remove_member: (p) => isBoundedId(p.targetUserId),
  change_role: (p) => isBoundedId(p.targetUserId) && isRole(p.newRole),
  create_environment: shapeCreateEnvironment,
  rotate_epoch: shapeRotateEpoch,
  grant_server: shapeGrantServer,
  revoke_server: (p) => isHexOfLength(p.serverKeyFingerprintHex, FINGERPRINT_BYTES),
};

function operationShapeOk(entry: ChainEntry): boolean {
  // 未知の op は表引きの**前**に membership で拒否する(deepsec B12): TS 型は
  // op の網羅を主張するが、入力はサーバー配布 JSON のキャストであり乖離しうる。
  // 確認せずに PAYLOAD_SHAPES[entry.op] を呼ぶと TypeError となり、「不正入力は
  // invalid-payload を返し throw しない」という公開 verifier の契約に反する。
  // Object.hasOwn は "__proto__" / "toString" 等のプロトタイプ由来の名前も
  // 自有プロパティでないとして正しく拒否する
  if (typeof entry.op !== "string" || !Object.hasOwn(PAYLOAD_SHAPES, entry.op)) {
    return false;
  }
  return PAYLOAD_SHAPES[entry.op](entry.payload as never);
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
  if (record.keyFingerprintHex !== entry.actor.keyFingerprintHex) {
    return { reason: "actor-key-mismatch" };
  }
  return { sigPubHex: record.sigPubHex };
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
    // 「不信入力で throw しない」契約を保つ。ループ末尾の computeChainEntryHash は
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

function applyGenesis(
  entry: ChainEntry & { readonly op: "genesis" },
  state: MutableChainState,
): ChainInvalidReason | null {
  state.members.set(entry.actor.userId, {
    userId: entry.actor.userId,
    role: "owner",
    encPubHex: entry.payload.encPubHex,
    sigPubHex: entry.payload.sigPubHex,
    keyFingerprintHex: entry.actor.keyFingerprintHex,
  });
  // genesis 時点のメンバー集合は空なので鍵重複は構造上生じない(§6.2)。
  // 以後の add_member の比較対象として owner の鍵も索引に載せる
  state.memberEncPubs.add(entry.payload.encPubHex);
  state.memberSigPubs.add(entry.payload.sigPubHex);
  return null;
}

async function applyAddMember(
  entry: ChainEntry & { readonly op: "add_member" },
  state: MutableChainState,
  actorRole: Role,
): Promise<ChainInvalidReason | null> {
  if (!atLeast(actorRole, "admin")) {
    return "insufficient-role";
  }
  // admin / owner ロールの付与は owner のみ(§6.2)
  if (atLeast(entry.payload.role, "admin") && actorRole !== "owner") {
    return "insufficient-role";
  }
  if (state.members.has(entry.payload.targetUserId)) {
    return "duplicate-member";
  }
  // メンバー鍵の一意性(§6.2。2026-08-03 決定): enc / sig のいずれかが現メンバー
  // 集合の同種鍵と一致する追加を拒否する。判定は個別鍵単位(FP 単位ではない —
  // 片鍵だけ流用したソック垢も拒否)。禁止範囲は現メンバー集合のみで、削除済み
  // メンバーの同一鍵 re-add(同一人物の復帰)は拒否しない。検査順序(role →
  // duplicate-member → 本検査)はテストベクターの期待理由が固定する
  if (
    state.memberEncPubs.has(entry.payload.encPubHex) ||
    state.memberSigPubs.has(entry.payload.sigPubHex)
  ) {
    return "duplicate-member-key";
  }
  state.members.set(entry.payload.targetUserId, {
    userId: entry.payload.targetUserId,
    role: entry.payload.role,
    encPubHex: entry.payload.encPubHex,
    sigPubHex: entry.payload.sigPubHex,
    keyFingerprintHex: await userFingerprintHex(entry.payload.encPubHex, entry.payload.sigPubHex),
  });
  state.memberEncPubs.add(entry.payload.encPubHex);
  state.memberSigPubs.add(entry.payload.sigPubHex);
  return null;
}

/**
 * remove_member / change_role 共通の前段: actor は admin 以上、対象は現メンバー、
 * admin / owner が対象のときは owner のみ(§6.2)
 */
function resolveTargetedOp(
  state: MutableChainState,
  actorRole: Role,
  targetUserId: string,
): ChainMember | ChainInvalidReason {
  if (!atLeast(actorRole, "admin")) {
    return "insufficient-role";
  }
  const target = state.members.get(targetUserId);
  if (target === undefined) {
    return "unknown-target";
  }
  if (atLeast(target.role, "admin") && actorRole !== "owner") {
    return "insufficient-role";
  }
  return target;
}

function applyRemoveMember(
  entry: ChainEntry & { readonly op: "remove_member" },
  state: MutableChainState,
  actorRole: Role,
): ChainInvalidReason | null {
  const target = resolveTargetedOp(state, actorRole, entry.payload.targetUserId);
  if (typeof target === "string") {
    return target;
  }
  if (target.role === "owner" && ownersCount(state) === 1) {
    return "last-owner-protected";
  }
  state.members.delete(target.userId);
  state.memberEncPubs.delete(target.encPubHex);
  state.memberSigPubs.delete(target.sigPubHex);
  return null;
}

function applyChangeRole(
  entry: ChainEntry & { readonly op: "change_role" },
  state: MutableChainState,
  actorRole: Role,
): ChainInvalidReason | null {
  const target = resolveTargetedOp(state, actorRole, entry.payload.targetUserId);
  if (typeof target === "string") {
    return target;
  }
  // 新 role が admin / owner の場合も owner のみ(現 role 側は resolveTargetedOp が検査済み)
  if (atLeast(entry.payload.newRole, "admin") && actorRole !== "owner") {
    return "insufficient-role";
  }
  if (target.role === "owner" && entry.payload.newRole !== "owner" && ownersCount(state) === 1) {
    return "last-owner-protected";
  }
  state.members.set(target.userId, { ...target, role: entry.payload.newRole });
  return null;
}

async function applyGrantServer(
  entry: ChainEntry & { readonly op: "grant_server" },
  state: MutableChainState,
  actorRole: Role,
): Promise<ChainInvalidReason | null> {
  // 認可段の検査順序(§6.2。2026-08-12 — ベクターで固定): role 規則 →
  // 再 grant 規則(§6.3)→ サーバー鍵の重複。FP 整合は payload 自体の
  // 自己整合(§9)であり role の直後に検査する(従来位置を維持)
  if (actorRole !== "owner") {
    return "insufficient-role";
  }
  // サーバー鍵 FP = SHA-256(server_enc_pub)[:16](enc 鍵のみ。§9 / ベクター定義)
  const encPub = decodeHex(entry.payload.serverEncPubHex) ?? new Uint8Array(0);
  const digest = await sha256(encPub);
  if (encodeHex(digest.slice(0, FINGERPRINT_BYTES)) !== entry.payload.serverKeyFingerprintHex) {
    return "invalid-payload";
  }
  // 同一サーバー鍵への再 grant の二層判定(2026-08-02 所有者裁定。2026-08-12 二層化):
  // 開示スコープはスコープ拡大(旧 ⊆ 新)のみ受理する。縮小を許すと revoke_server +
  // rotate_epoch(§7 の全環境ローテーション義務)を迂回して「開示を止めたつもり」に
  // なれてしまうため、縮小は必ず失効経路を通す。拡大は未開示環境を足すだけなので無害。
  // 一方 lease_policy は自由改訂(縮小・全削除を含む): ポリシーはリース経路(§9.1)の
  // ACL であり、サーバーの既知 DEK 集合を変えない(§6.3 — 判定はフィールドごとに独立)
  const existing = state.serverGrants.get(entry.payload.serverKeyFingerprintHex);
  if (existing !== undefined) {
    const newScope = new Set(entry.payload.scopeEnvironmentIds);
    if (existing.scopeEnvironmentIds.some((id) => !newScope.has(id))) {
      return "grant-scope-narrowed";
    }
  }
  // サーバー鍵の一意性(§6.2。2026-08-12): サーバー enc 公開鍵が現メンバーの
  // enc 公開鍵と一致する grant は拒否する(「鍵 → 主体」逆引きの一意性の
  // 受信者クラス横断版)。逆方向(有効 grant のサーバー鍵を add_member に流用)は
  // 仕様の明示的な対象外のまま(§6.2 メンバー鍵一意性の「注意」)
  if (state.memberEncPubs.has(entry.payload.serverEncPubHex)) {
    return "duplicate-server-key";
  }
  state.serverGrants.set(entry.payload.serverKeyFingerprintHex, {
    serverKeyFingerprintHex: entry.payload.serverKeyFingerprintHex,
    serverEncPubHex: entry.payload.serverEncPubHex,
    // 再 grant では有効 grant を確立したエントリが置き換わるため seq も前進する
    // (AUDIT_SPEC §3.5 の grant_chain_seq の出所 — chain-entries.json の
    // valid_appends `regrant-lease-policy-revised` が 9 → 10 の前進を固定する)
    grantSeq: entry.seq,
    scopeEnvironmentIds: [...entry.payload.scopeEnvironmentIds],
    leasePolicy: entry.payload.leasePolicy.map((element) => ({
      issuerUrl: element.issuerUrl,
      audience: element.audience,
      claimConstraints: element.claimConstraints.map((constraint) => ({ ...constraint })),
    })),
  });
  return null;
}

function applyRevokeServer(
  entry: ChainEntry & { readonly op: "revoke_server" },
  state: MutableChainState,
  actorRole: Role,
): ChainInvalidReason | null {
  if (actorRole !== "owner") {
    return "insufficient-role";
  }
  if (!state.serverGrants.delete(entry.payload.serverKeyFingerprintHex)) {
    return "unknown-server-grant";
  }
  return null;
}

// 環境の初期エポック(create_environment 直後の値 — CRYPTO_SPEC §3 / §6.2)
const INITIAL_EPOCH = 1;

function applyCreateEnvironment(
  entry: ChainEntry & { readonly op: "create_environment" },
  state: MutableChainState,
  actorRole: Role,
): ChainInvalidReason | null {
  if (!atLeast(actorRole, "member")) {
    return "insufficient-role";
  }
  // environment_id はチェーン履歴全体で一意(§6.2)。チェーンは環境の削除を
  // 観測しない(削除はデータプレーン操作)ため、environments マップは削除されず、
  // 削除済み環境 ID の再作成もここで拒否される(ID 再利用禁止の合意規則昇格)
  if (state.environments.has(entry.payload.environmentId)) {
    return "duplicate-environment";
  }
  state.environments.set(entry.payload.environmentId, {
    currentEpoch: INITIAL_EPOCH,
    createdAtSeq: entry.seq,
    epochStartSeqs: new Map([[INITIAL_EPOCH, entry.seq]]),
    dekCommitments: new Map([[INITIAL_EPOCH, entry.payload.dekCommitmentHex]]),
  });
  return null;
}

function applyRotateEpoch(
  entry: ChainEntry & { readonly op: "rotate_epoch" },
  state: MutableChainState,
  actorRole: Role,
): ChainInvalidReason | null {
  if (!atLeast(actorRole, "member")) {
    return "insufficient-role";
  }
  // 認可段の検査順序(§6.2。ベクターで固定): role → unknown-environment →
  // エポック順序。当該 environment_id の create_environment が先行していなければ
  // 無効(「未観測なら初期値 1」の既定値フォールバックは廃止 — 2026-08-03)
  const environment = state.environments.get(entry.payload.environmentId);
  if (environment === undefined) {
    return "unknown-environment";
  }
  // エポックは環境ごとのカウンタで必ず +1(2026-08-02 所有者裁定・案 3)。
  // 巻き戻し(削除済みメンバーが保持する旧 DEK で新しい値が暗号化される)、
  // 重複、ジャンプ(member 権限の 1 署名で safe integer 上限まで飛ばして
  // 以後のローテーションを不能にする DoS)をすべて拒否する
  if (entry.payload.newEpoch !== environment.currentEpoch + 1) {
    return "epoch-out-of-sequence";
  }
  environment.currentEpoch = entry.payload.newEpoch;
  environment.epochStartSeqs.set(entry.payload.newEpoch, entry.seq);
  environment.dekCommitments.set(entry.payload.newEpoch, entry.payload.dekCommitmentHex);
  return null;
}

async function applyOperation(
  entry: ChainEntry,
  state: MutableChainState,
  actorRole: Role,
): Promise<ChainInvalidReason | null> {
  switch (entry.op) {
    case "genesis":
      return applyGenesis(entry, state);
    case "add_member":
      return applyAddMember(entry, state, actorRole);
    case "remove_member":
      return applyRemoveMember(entry, state, actorRole);
    case "change_role":
      return applyChangeRole(entry, state, actorRole);
    case "create_environment":
      return applyCreateEnvironment(entry, state, actorRole);
    case "rotate_epoch":
      return applyRotateEpoch(entry, state, actorRole);
    case "grant_server":
      return applyGrantServer(entry, state, actorRole);
    case "revoke_server":
      return applyRevokeServer(entry, state, actorRole);
  }
}

/** 適用済み状態から対象メンバーの鍵束縛を引いて tenure 開始を記録する。 */
function recordTenureStartOf(
  history: ChainHistoryBuilder,
  state: MutableChainState,
  userId: string,
  seq: number,
  role: Role,
): void {
  const member = state.members.get(userId);
  if (member !== undefined) {
    history.recordTenureStart(userId, seq, member, member.keyFingerprintHex, role);
  }
}

/**
 * 適用成功済みエントリを履歴索引(chain-history.ts)へ記録する。tenure の
 * 開始・終了・role 変更はすべて当該エントリ自身の seq を境界にする
 * (§6.3 の inclusive 規約 — value-signature.json のベクターが固定)。
 */
function recordHistory(
  history: ChainHistoryBuilder,
  entry: ChainEntry,
  state: MutableChainState,
): void {
  switch (entry.op) {
    case "genesis":
      recordTenureStartOf(history, state, entry.actor.userId, entry.seq, "owner");
      return;
    case "add_member":
      recordTenureStartOf(
        history,
        state,
        entry.payload.targetUserId,
        entry.seq,
        entry.payload.role,
      );
      return;
    case "change_role":
      history.recordRoleChange(entry.payload.targetUserId, entry.seq, entry.payload.newRole);
      return;
    case "remove_member":
      history.recordTenureEnd(entry.payload.targetUserId, entry.seq);
      return;
    case "create_environment":
      history.recordEnvironmentCreated(entry.payload.environmentId, entry.seq);
      return;
    case "rotate_epoch":
      history.recordEpochRotated(entry.payload.environmentId, entry.payload.newEpoch, entry.seq);
      return;
    case "grant_server":
    case "revoke_server":
      return;
  }
}

/**
 * 適用前の 1 エントリ検査(検証段順: フレーミング → payload 構造 → actor 解決 →
 * 署名)。null = 通過。認可 + 状態遷移は applyOperation が続けて検査する。
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
    memberEncPubs: new Set(),
    memberSigPubs: new Set(),
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
    // actor は resolveActorSigPub で存在確認済み(genesis は owner として自己記述)
    const actorRole = state.members.get(entry.actor.userId)?.role ?? "reader";
    const applied = await applyOperation(entry, state, actorRole);
    if (applied !== null) {
      return fail(applied);
    }
    if (history !== null) {
      recordHistory(history, entry, state);
    }
    prevHash = await computeChainEntryHash(entry);
    history?.recordEntryHash(prevHash);
  }

  return {
    ok: true,
    value: {
      members: state.members,
      serverGrants: state.serverGrants,
      environments: state.environments,
      headSeq: entries.length,
      headHashHex: prevHash,
    },
  };
}

/**
 * Verifies a full membership chain (CRYPTO_SPEC §6.3): framing, payload
 * shape, actor identity, Ed25519 signatures and the §6.2 role rules — and
 * derives the resulting state (current members with roles, active server
 * grants, observed environment epochs, chain head).
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
