// メンバーシップログ(CRYPTO_SPEC §6)のワイヤ表現。
//
// フィールドは @maruhi/crypto の ChainEntry と構造的に一致させ、デコード結果を
// そのまま verifyChain へ渡せるようにする(サーバー側の詰め替え層を作らない)。
//
// 検証の権威は verifyChain(§6.3 / §6.4)である。Schema はトランスポート形状のみを
// 検査する: 固定長 hex は安価かつ正確に弾けるためここで検査するが、自由文字列の
// サイズ上限(§6.1 の合意規則)は意図的に Schema へ重複させない — 上限超過は
// verifyChain の `invalid-payload`(テストベクターで固定された理由コード)として
// 一貫して報告されるべきで、Schema での 400 と二重の拒否経路を作らないため。

import { EnvironmentIdSchema } from "@maruhi/core";
import type { ChainEntry, ProposableOperation } from "@maruhi/crypto";
import { Schema } from "effect";

import { KeyFingerprintHex, PublicKeyHex, Sha256Hex, SignatureHex } from "./hex.ts";

/** Chain role (CRYPTO_SPEC §6.2). */
export const RoleSchema = Schema.Literals(["owner", "admin", "member", "reader"]);

/** Entry actor: internal user id + key fingerprint only (CRYPTO_SPEC §6.1). */
export const ChainActorSchema = Schema.Struct({
  // userId は意図的に bound しない(§6.1 の自由文字列上限は verifyChain が検査する)
  userId: Schema.String,
  keyFingerprintHex: KeyFingerprintHex,
});

const entryBaseFields = {
  suite: Schema.String,
  seq: Schema.Number,
  prevHashHex: Sha256Hex,
  actor: ChainActorSchema,
  timestampMs: Schema.Number,
  signatureHex: SignatureHex,
};

/** Member scope kind (CRYPTO_SPEC §6.2 — 2026-09-14 ES). */
export const ScopeKindSchema = Schema.Literals(["all", "listed"]);

/**
 * The two trailing scope fields of `add_member` / `change_role` (CRYPTO_SPEC
 * §6.2). ワイヤは environment_id の構造化リストを as-signed 順で運ぶ(正規化 =
 * 入れ子 LP は crypto 側)。`all` ⇒ 空リスト・256 以下・重複なしは合意規則であり
 * verifyChain が `invalid-payload` で検査する(冒頭の方針どおり Schema へ重複させない)
 */
const scopePayloadFields = {
  scopeKind: ScopeKindSchema,
  scopeEnvironmentIds: Schema.Array(Schema.String),
};

const GenesisPayloadSchema = Schema.Struct({ encPubHex: PublicKeyHex, sigPubHex: PublicKeyHex });

const AddMemberPayloadSchema = Schema.Struct({
  targetUserId: Schema.String,
  encPubHex: PublicKeyHex,
  sigPubHex: PublicKeyHex,
  role: RoleSchema,
  ...scopePayloadFields,
});

const RemoveMemberPayloadSchema = Schema.Struct({ targetUserId: Schema.String });

const ChangeRolePayloadSchema = Schema.Struct({
  targetUserId: Schema.String,
  newRole: RoleSchema,
  ...scopePayloadFields,
});

const GenesisEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("genesis"),
  payload: GenesisPayloadSchema,
});

const AddMemberEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("add_member"),
  payload: AddMemberPayloadSchema,
});

const RemoveMemberEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("remove_member"),
  payload: RemoveMemberPayloadSchema,
});

const ChangeRoleEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("change_role"),
  payload: ChangeRolePayloadSchema,
});

/**
 * `create_environment` entry (CRYPTO_SPEC §6.2): carries the
 * epoch-1 DEK commitment (§5.2). Submitted only through the composite
 * environment-creation endpoint (AUTH_SPEC §12-4) — the generic append
 * rejects it (§6). Exported for that endpoint's payload schema.
 *
 * environmentId は §12-1 の受理ポリシー形式(EnvironmentIdSchema)で検査する:
 * 複合化で ID の運搬が旧 payload からチェーンエントリ内へ移り、URL 座標も
 * 持たないため、ここが唯一のワイヤ受理点になる(形式は合意規則ではない —
 * チェーン検証は §6.1 の bounded string のみを要求する。緩い形式の ID を
 * 受理すると URL param を持つ後続エンドポイント — rotate / rename / delete /
 * pull — から到達不能な環境が生まれ、§7 の全環境ローテーション義務も破れる)。
 */
const CreateEnvironmentPayloadSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  dekCommitmentHex: Sha256Hex,
});

export const CreateEnvironmentEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("create_environment"),
  payload: CreateEnvironmentPayloadSchema,
});

/**
 * `rotate_epoch` entry: carries the new-epoch DEK commitment (§5.2).
 * Submitted only through the composite rotation endpoint
 * (AUTH_SPEC §12-4). Exported for that endpoint's payload schema.
 */
const RotateEpochPayloadSchema = Schema.Struct({
  // create_environment と同じ受理ポリシー形式(URL 座標との一致検査 —
  // §12-4 — の対象だが、ワイヤ側でも同じ形式に固定して非対称を作らない)
  environmentId: EnvironmentIdSchema,
  newEpoch: Schema.Number,
  reason: Schema.String,
  dekCommitmentHex: Sha256Hex,
});

export const RotateEpochEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("rotate_epoch"),
  payload: RotateEpochPayloadSchema,
});

/**
 * One exact-match claim constraint of a grant_server lease policy element
 * (CRYPTO_SPEC §6.2)。サイズ上限(要素 8 / 制約 8 / 各文字列 1024 バイト)は
 * 合意規則であり verifyChain が検査する(Schema へ重複させない — 冒頭の方針)。
 */
const LeaseClaimConstraintSchema = Schema.Struct({
  claimName: Schema.String,
  claimValue: Schema.String,
});

/** One issuer element of a grant_server lease policy (CRYPTO_SPEC §6.2 / §9.1). */
const LeasePolicyIssuerSchema = Schema.Struct({
  issuerUrl: Schema.String,
  audience: Schema.String,
  claimConstraints: Schema.Array(LeaseClaimConstraintSchema),
});

const GrantServerPayloadSchema = Schema.Struct({
  serverEncPubHex: PublicKeyHex,
  serverKeyFingerprintHex: KeyFingerprintHex,
  scopeEnvironmentIds: Schema.Array(Schema.String),
  // ワイヤは構造化リストを as-signed 順で運ぶ(正規化 = 3 段入れ子 LP は
  // crypto 側 — 順序は署名対象の一部なのでオブジェクトでなく配列で保つ)
  leasePolicy: Schema.Array(LeasePolicyIssuerSchema),
});

const GrantServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("grant_server"),
  payload: GrantServerPayloadSchema,
});

const RevokeServerPayloadSchema = Schema.Struct({ serverKeyFingerprintHex: KeyFingerprintHex });

const RevokeServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("revoke_server"),
  payload: RevokeServerPayloadSchema,
});

/**
 * One environment tuple of a `checkpoint` payload (CRYPTO_SPEC §6.2)。
 * environmentId は create/rotate と同じ受理ポリシー
 * 形式。epoch / manifestVersion の数値範囲・重複 environment_id・
 * audit_head の「空または 64 hex」は合意規則であり verifyChain が検査する
 * (冒頭の方針どおり Schema へ重複させない。固定長 hex のみここで検査)。
 */
const CheckpointEnvironmentEntrySchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  epoch: Schema.Number,
  manifestVersion: Schema.Number,
  manifestSigHashHex: Sha256Hex,
  valuesDigestHex: Sha256Hex,
});

/**
 * `checkpoint` entry (CRYPTO_SPEC §6.2): the issuer's attestation of its
 * verified data-layer view. Boundary checkpoints are submitted only through
 * the composite create/rotate endpoints (AUTH_SPEC §12-4);
 * standalone (periodic) checkpoints flow through the generic append with
 * acceptance-time content matching (AUTH_SPEC §16-2). Exported for
 * the composite payload schemas (data-api.ts).
 */
const CheckpointPayloadSchema = Schema.Struct({
  // ワイヤは構造化リストを as-signed 順で運ぶ(正規化 = 入れ子 LP は
  // crypto 側 — 順序は署名対象の一部なので配列で保つ。grant_server と同型)
  environments: Schema.Array(CheckpointEnvironmentEntrySchema),
  // 空文字列 = 監査ヘッドの公証なし(§6.2)。「空または 64 hex」の判定は
  // 合意規則(verifyChain)に一本化する
  auditHeadHashHex: Schema.String,
});

export const CheckpointEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("checkpoint"),
  payload: CheckpointPayloadSchema,
});

// ---------------------------------------------------------------------------
// 四眼(CRYPTO_SPEC §6.2 — 2026-09-14 PF1)

/** Operations a four-eyes policy may name (CRYPTO_SPEC §6.2 — the closed target set). */
const ApprovalTargetOpSchema = Schema.Literals([
  "grant_server",
  "revoke_server",
  "remove_member",
  "change_role",
  "add_member",
  "set_approval_policy",
]);

/**
 * `set_approval_policy` payload: ops は as-signed 順の配列(正規化 = 入れ子 LP は
 * crypto 側)。required_approvals の「0 または 2 以上」・ops の閉集合検査は合意規則
 * (verifyChain)— ここでは閉集合のリテラルだけを型として持つ(ワイヤ型と crypto 型の
 * 一致のため)
 */
const SetApprovalPolicyPayloadSchema = Schema.Struct({
  ops: Schema.Array(ApprovalTargetOpSchema),
  requiredApprovals: Schema.Number,
});

const SetApprovalPolicyEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("set_approval_policy"),
  payload: SetApprovalPolicyPayloadSchema,
});

/**
 * `add_device` payload (CRYPTO_SPEC §6.2 — 2026-09-19 DK): the actor's new
 * device key and its cap. The scope pair reuses the member-scope fields (same
 * encoding and structure rules — verifyChain checks them as `invalid-payload`).
 */
const AddDevicePayloadSchema = Schema.Struct({
  encPubHex: PublicKeyHex,
  sigPubHex: PublicKeyHex,
  roleCap: RoleSchema,
  ...scopePayloadFields,
});

/**
 * `revoke_device` payload (CRYPTO_SPEC §6.2 — 2026-09-19 DK): the target and the
 * fingerprints of that member's devices to revoke, carried as-signed (the nested
 * length-prefixed canonical form is computed by the crypto layer). 1..256 entries
 * and no duplicates are consensus rules (`invalid-payload`), not Schema checks.
 */
const RevokeDevicePayloadSchema = Schema.Struct({
  targetUserId: Schema.String,
  deviceFingerprintsHex: Schema.Array(KeyFingerprintHex),
});

/**
 * An operation carried inside a `propose` entry (CRYPTO_SPEC §6.2): any
 * non-approval operation as `{ op, payload }` — structured on the wire, the
 * `inner_payload_lp_hex` canonical form is computed by the crypto layer.
 * `propose` / `approve` / `withdraw` are not members (提案の入れ子は構造段で無効).
 */
const ProposableOperationSchema = Schema.Union([
  Schema.Struct({ op: Schema.Literal("genesis"), payload: GenesisPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("add_member"), payload: AddMemberPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("remove_member"), payload: RemoveMemberPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("change_role"), payload: ChangeRolePayloadSchema }),
  Schema.Struct({
    op: Schema.Literal("create_environment"),
    payload: CreateEnvironmentPayloadSchema,
  }),
  Schema.Struct({ op: Schema.Literal("rotate_epoch"), payload: RotateEpochPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("grant_server"), payload: GrantServerPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("revoke_server"), payload: RevokeServerPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("checkpoint"), payload: CheckpointPayloadSchema }),
  Schema.Struct({
    op: Schema.Literal("set_approval_policy"),
    payload: SetApprovalPolicyPayloadSchema,
  }),
  // 端末鍵の 2 op(2026-09-19 DK)は構造上は内側 op になれるが、方針の対象にはなりえない
  // (`approval-not-required` — CRYPTO_SPEC §6.2「四眼との関係」。verifyChain が判定する)
  Schema.Struct({ op: Schema.Literal("add_device"), payload: AddDevicePayloadSchema }),
  Schema.Struct({ op: Schema.Literal("revoke_device"), payload: RevokeDevicePayloadSchema }),
]);

const ProposeEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("propose"),
  payload: Schema.Struct({
    inner: ProposableOperationSchema,
    // 非負の安全整数は合意規則(verifyChain の invalid-payload)
    expiresAtMs: Schema.Number,
  }),
});

/** `approve` / `withdraw` payload: the `propose` entry hash (CRYPTO_SPEC §6.2). */
const ProposalRefPayloadSchema = Schema.Struct({ proposalHashHex: Sha256Hex });

const ApproveEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("approve"),
  payload: ProposalRefPayloadSchema,
});

const WithdrawEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("withdraw"),
  payload: ProposalRefPayloadSchema,
});

const AddDeviceEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("add_device"),
  payload: AddDevicePayloadSchema,
});

const RevokeDeviceEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("revoke_device"),
  payload: RevokeDevicePayloadSchema,
});

/** Wire schema for one signed chain entry, discriminated by `op` (CRYPTO_SPEC §6.1). */
export const ChainEntrySchema = Schema.Union([
  GenesisEntrySchema,
  AddMemberEntrySchema,
  RemoveMemberEntrySchema,
  ChangeRoleEntrySchema,
  CreateEnvironmentEntrySchema,
  RotateEpochEntrySchema,
  GrantServerEntrySchema,
  RevokeServerEntrySchema,
  CheckpointEntrySchema,
  SetApprovalPolicyEntrySchema,
  ProposeEntrySchema,
  ApproveEntrySchema,
  WithdrawEntrySchema,
  // 端末鍵(CRYPTO_SPEC §6.2 — 2026-09-19 DK)。サーバーは K3 まで DeviceOpsNotAccepted で拒否する
  AddDeviceEntrySchema,
  RevokeDeviceEntrySchema,
]);

// デコード結果が @maruhi/crypto の ChainEntry へそのまま渡せることの静的検査。
// (ワイヤ型が crypto 型から乖離したらここがコンパイルエラーになる)
type WireChainEntry = typeof ChainEntrySchema.Type;
type WireIsChainEntry = WireChainEntry extends ChainEntry ? true : never;
const wireIsChainEntry: WireIsChainEntry = true;
void wireIsChainEntry;
type WireProposable = typeof ProposableOperationSchema.Type;
type WireIsProposable = WireProposable extends ProposableOperation ? true : never;
const wireIsProposable: WireIsProposable = true;
void wireIsProposable;
