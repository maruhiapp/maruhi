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
import type { ChainEntry, ChainMember, ChainState, Role, ServerGrant } from "./chain-types.ts";
import type { ChainInvalidReason, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { SUITE_ID } from "./suite.ts";

const GENESIS_PREV_HASH = "0".repeat(64);
const ROLE_RANK: Readonly<Record<Role, number>> = { reader: 0, member: 1, admin: 2, owner: 3 };
const ROLES: readonly Role[] = ["owner", "admin", "member", "reader"];
const FINGERPRINT_BYTES = 16;
// フィールドサイズ上限(CRYPTO_SPEC §6.1。2026-08-02 決定): チェーン有効性の
// 合意規則。巨大 payload による検証クライアントの資源消費(可用性)対策
const MAX_FIELD_BYTES = 1024;
const MAX_SCOPE_ENVIRONMENTS = 256;

interface MutableChainState {
  readonly members: Map<string, ChainMember>;
  readonly serverGrants: Map<string, ServerGrant>;
  readonly environmentEpochs: Map<string, number>;
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
  if (typeof value !== "string") {
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
  if (
    !isRecord(entry.actor) ||
    !isBoundedId(entry.actor.userId) ||
    typeof entry.actor.keyFingerprintHex !== "string"
  ) {
    return "invalid-payload";
  }
  if (typeof entry.signatureHex !== "string") {
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

function shapeRotateEpoch(p: {
  environmentId: unknown;
  newEpoch: unknown;
  reason: unknown;
}): boolean {
  return (
    isBoundedId(p.environmentId) &&
    Number.isSafeInteger(p.newEpoch) &&
    (p.newEpoch as number) >= 1 &&
    typeof p.reason === "string" &&
    withinFieldBytes(p.reason)
  );
}

function shapeGrantServer(p: {
  serverEncPubHex: unknown;
  serverKeyFingerprintHex: unknown;
  scopeEnvironmentIds: unknown;
}): boolean {
  return (
    isHexOfLength(p.serverEncPubHex, 32) &&
    isHexOfLength(p.serverKeyFingerprintHex, FINGERPRINT_BYTES) &&
    Array.isArray(p.scopeEnvironmentIds) &&
    p.scopeEnvironmentIds.length <= MAX_SCOPE_ENVIRONMENTS &&
    p.scopeEnvironmentIds.every((id) => isBoundedId(id))
  );
}

function operationShapeOk(entry: ChainEntry): boolean {
  switch (entry.op) {
    case "genesis":
      return shapeGenesis(entry.payload);
    case "add_member":
      return shapeAddMember(entry.payload);
    case "remove_member":
      return isBoundedId(entry.payload.targetUserId);
    case "change_role":
      return isBoundedId(entry.payload.targetUserId) && isRole(entry.payload.newRole);
    case "rotate_epoch":
      return shapeRotateEpoch(entry.payload);
    case "grant_server":
      return shapeGrantServer(entry.payload);
    case "revoke_server":
      return isHexOfLength(entry.payload.serverKeyFingerprintHex, FINGERPRINT_BYTES);
  }
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
  if (signature === null || signature.length !== 64 || publicKeyBytes === null) {
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
  state.members.set(entry.payload.targetUserId, {
    userId: entry.payload.targetUserId,
    role: entry.payload.role,
    encPubHex: entry.payload.encPubHex,
    sigPubHex: entry.payload.sigPubHex,
    keyFingerprintHex: await userFingerprintHex(entry.payload.encPubHex, entry.payload.sigPubHex),
  });
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
  if (actorRole !== "owner") {
    return "insufficient-role";
  }
  // サーバー鍵 FP = SHA-256(server_enc_pub)[:16](enc 鍵のみ。§9 / ベクター定義)
  const encPub = decodeHex(entry.payload.serverEncPubHex) ?? new Uint8Array(0);
  const digest = await sha256(encPub);
  if (encodeHex(digest.slice(0, FINGERPRINT_BYTES)) !== entry.payload.serverKeyFingerprintHex) {
    return "invalid-payload";
  }
  // 同一サーバー鍵への再 grant はスコープ拡大(旧 ⊆ 新)のみ受理する(2026-08-02
  // 所有者裁定)。縮小を許すと revoke_server + rotate_epoch(§7 の全環境ローテー
  // ション義務)を迂回して「開示を止めたつもり」になれてしまうため、縮小は必ず
  // 失効経路を通す。拡大は未開示環境を足すだけなので無害
  const existing = state.serverGrants.get(entry.payload.serverKeyFingerprintHex);
  if (existing !== undefined) {
    const newScope = new Set(entry.payload.scopeEnvironmentIds);
    if (existing.scopeEnvironmentIds.some((id) => !newScope.has(id))) {
      return "grant-scope-narrowed";
    }
  }
  state.serverGrants.set(entry.payload.serverKeyFingerprintHex, {
    serverKeyFingerprintHex: entry.payload.serverKeyFingerprintHex,
    serverEncPubHex: entry.payload.serverEncPubHex,
    scopeEnvironmentIds: [...entry.payload.scopeEnvironmentIds],
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

// 環境の初期エポック(環境作成は平文メタデータでチェーン外だが、エポックは常に 1 から始まる)
const INITIAL_EPOCH = 1;

function applyRotateEpoch(
  entry: ChainEntry & { readonly op: "rotate_epoch" },
  state: MutableChainState,
  actorRole: Role,
): ChainInvalidReason | null {
  if (!atLeast(actorRole, "member")) {
    return "insufficient-role";
  }
  // エポックは環境ごとのカウンタで必ず +1(2026-08-02 所有者裁定・案 3)。
  // 巻き戻し(削除済みメンバーが保持する旧 DEK で新しい値が暗号化される)、
  // 重複、ジャンプ(member 権限の 1 署名で safe integer 上限まで飛ばして
  // 以後のローテーションを不能にする DoS)をすべて拒否する
  const observed = state.environmentEpochs.get(entry.payload.environmentId) ?? INITIAL_EPOCH;
  if (entry.payload.newEpoch !== observed + 1) {
    return "epoch-out-of-sequence";
  }
  state.environmentEpochs.set(entry.payload.environmentId, entry.payload.newEpoch);
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
    case "rotate_epoch":
      return applyRotateEpoch(entry, state, actorRole);
    case "grant_server":
      return applyGrantServer(entry, state, actorRole);
    case "revoke_server":
      return applyRevokeServer(entry, state, actorRole);
  }
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
  if (entries.length === 0) {
    return { ok: false, error: { kind: "ChainInvalid", seq: 0, reason: "empty-chain" } };
  }
  const state: MutableChainState = {
    members: new Map(),
    serverGrants: new Map(),
    environmentEpochs: new Map(),
  };
  let prevHash = GENESIS_PREV_HASH;
  let seq = 0;
  const fail = (reason: ChainInvalidReason) =>
    ({ ok: false, error: { kind: "ChainInvalid", seq, reason } }) as const;

  for (const [index, entry] of entries.entries()) {
    seq = index + 1;
    const framing = checkFraming(entry, seq, prevHash);
    if (framing !== null) {
      return fail(framing);
    }
    const shape = checkPayloadShape(entry);
    if (shape !== null) {
      return fail(shape);
    }
    const actor = await resolveActorSigPub(entry, state);
    if ("reason" in actor) {
      return fail(actor.reason);
    }
    if (!(await verifyEntrySignature(entry, actor.sigPubHex))) {
      return fail("bad-signature");
    }
    // actor は resolveActorSigPub で存在確認済み(genesis は owner として自己記述)
    const actorRole = state.members.get(entry.actor.userId)?.role ?? "reader";
    const applied = await applyOperation(entry, state, actorRole);
    if (applied !== null) {
      return fail(applied);
    }
    prevHash = await computeChainEntryHash(entry);
  }

  return {
    ok: true,
    value: {
      members: state.members,
      serverGrants: state.serverGrants,
      environmentEpochs: state.environmentEpochs,
      headSeq: entries.length,
      headHashHex: prevHash,
    },
  };
}
