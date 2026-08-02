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

import type { ChainEntry } from "@maruhi/crypto";
import { Schema } from "effect";

function hexString(bytes: number): Schema.String {
  return Schema.String.check(
    Schema.isPattern(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), {
      description: `lowercase hex (${bytes} bytes)`,
    }),
  );
}

const Hash256Hex = hexString(32);
const PublicKeyHex = hexString(32);
const FingerprintHex = hexString(16);
const SignatureHex = hexString(64);

/** Chain role (CRYPTO_SPEC §6.2). */
export const RoleSchema = Schema.Literals(["owner", "admin", "member", "reader"]);

/** Entry actor: internal user id + key fingerprint only (CRYPTO_SPEC §6.1). */
export const ChainActorSchema = Schema.Struct({
  userId: Schema.String,
  keyFingerprintHex: FingerprintHex,
});

const entryBaseFields = {
  suite: Schema.String,
  seq: Schema.Number,
  prevHashHex: Hash256Hex,
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

const RotateEpochEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("rotate_epoch"),
  payload: Schema.Struct({
    environmentId: Schema.String,
    newEpoch: Schema.Number,
    reason: Schema.String,
  }),
});

const GrantServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("grant_server"),
  payload: Schema.Struct({
    serverEncPubHex: PublicKeyHex,
    serverKeyFingerprintHex: FingerprintHex,
    scopeEnvironmentIds: Schema.Array(Schema.String),
  }),
});

const RevokeServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("revoke_server"),
  payload: Schema.Struct({ serverKeyFingerprintHex: FingerprintHex }),
});

/** Wire schema for one signed chain entry, discriminated by `op` (CRYPTO_SPEC §6.1). */
export const ChainEntrySchema = Schema.Union([
  GenesisEntrySchema,
  AddMemberEntrySchema,
  RemoveMemberEntrySchema,
  ChangeRoleEntrySchema,
  RotateEpochEntrySchema,
  GrantServerEntrySchema,
  RevokeServerEntrySchema,
]);

// デコード結果が @maruhi/crypto の ChainEntry へそのまま渡せることの静的検査。
// (ワイヤ型が crypto 型から乖離したらここがコンパイルエラーになる)
type WireChainEntry = typeof ChainEntrySchema.Type;
type WireIsChainEntry = WireChainEntry extends ChainEntry ? true : never;
const wireIsChainEntry: WireIsChainEntry = true;
void wireIsChainEntry;
