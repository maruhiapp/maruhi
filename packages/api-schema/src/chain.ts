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
import type { ChainEntry } from "@maruhi/crypto";
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

const GenesisEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("genesis"),
  payload: Schema.Struct({ encPubHex: PublicKeyHex, sigPubHex: PublicKeyHex }),
});

const AddMemberEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("add_member"),
  payload: Schema.Struct({
    targetUserId: Schema.String,
    encPubHex: PublicKeyHex,
    sigPubHex: PublicKeyHex,
    role: RoleSchema,
  }),
});

const RemoveMemberEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("remove_member"),
  payload: Schema.Struct({ targetUserId: Schema.String }),
});

const ChangeRoleEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("change_role"),
  payload: Schema.Struct({ targetUserId: Schema.String, newRole: RoleSchema }),
});

/**
 * `create_environment` entry (CRYPTO_SPEC §6.2, 2026-08-03): carries the
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
export const CreateEnvironmentEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("create_environment"),
  payload: Schema.Struct({
    environmentId: EnvironmentIdSchema,
    dekCommitmentHex: Sha256Hex,
  }),
});

/**
 * `rotate_epoch` entry: carries the new-epoch DEK commitment (§5.2,
 * 2026-08-03). Submitted only through the composite rotation endpoint
 * (AUTH_SPEC §12-4). Exported for that endpoint's payload schema.
 */
export const RotateEpochEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("rotate_epoch"),
  payload: Schema.Struct({
    // create_environment と同じ受理ポリシー形式(URL 座標との一致検査 —
    // §12-4 — の対象だが、ワイヤ側でも同じ形式に固定して非対称を作らない)
    environmentId: EnvironmentIdSchema,
    newEpoch: Schema.Number,
    reason: Schema.String,
    dekCommitmentHex: Sha256Hex,
  }),
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

const GrantServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("grant_server"),
  payload: Schema.Struct({
    serverEncPubHex: PublicKeyHex,
    serverKeyFingerprintHex: KeyFingerprintHex,
    scopeEnvironmentIds: Schema.Array(Schema.String),
    // ワイヤは構造化リストを as-signed 順で運ぶ(正規化 = 3 段入れ子 LP は
    // crypto 側 — 順序は署名対象の一部なのでオブジェクトでなく配列で保つ)
    leasePolicy: Schema.Array(LeasePolicyIssuerSchema),
  }),
});

const RevokeServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("revoke_server"),
  payload: Schema.Struct({ serverKeyFingerprintHex: KeyFingerprintHex }),
});

/**
 * One environment tuple of a `checkpoint` payload (CRYPTO_SPEC §6.2,
 * 2026-08-27 — PR-F3a)。environmentId は create/rotate と同じ受理ポリシー
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
 * the composite create/rotate endpoints (AUTH_SPEC §12-4 — PR-F3b);
 * standalone (periodic) checkpoints flow through the generic append
 * (AUTH_SPEC §16-2) once their acceptance-time content matching lands (M2 —
 * until then the generic append rejects the op, fail-closed). The composite
 * payload schemas (PR-F3b) will import this — exported then, not before
 * (未使用 export を置かない).
 */
const CheckpointEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("checkpoint"),
  payload: Schema.Struct({
    // ワイヤは構造化リストを as-signed 順で運ぶ(正規化 = 入れ子 LP は
    // crypto 側 — 順序は署名対象の一部なので配列で保つ。grant_server と同型)
    environments: Schema.Array(CheckpointEnvironmentEntrySchema),
    // 空文字列 = 監査ヘッドの公証なし(§6.2)。「空または 64 hex」の判定は
    // 合意規則(verifyChain)に一本化する
    auditHeadHashHex: Schema.String,
  }),
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
]);

// デコード結果が @maruhi/crypto の ChainEntry へそのまま渡せることの静的検査。
// (ワイヤ型が crypto 型から乖離したらここがコンパイルエラーになる)
type WireChainEntry = typeof ChainEntrySchema.Type;
type WireIsChainEntry = WireChainEntry extends ChainEntry ? true : never;
const wireIsChainEntry: WireIsChainEntry = true;
void wireIsChainEntry;
