// CRYPTO_SPEC §6: メンバーシップログ(署名付きハッシュチェーン)の型。
//
// アイデンティティ規則(絶対): 主体識別は内部 user_id と鍵フィンガープリントのみ。
// GitHub ID 等のプロバイダ情報・メールアドレスをこの構造に入れてはならない。

/** Project role on the membership chain (CRYPTO_SPEC §6.2). */
export type Role = "owner" | "admin" | "member" | "reader";

/** Chain operation kind (CRYPTO_SPEC §6.2). */
export type ChainOp =
  | "genesis"
  | "add_member"
  | "remove_member"
  | "change_role"
  | "rotate_epoch"
  | "grant_server"
  | "revoke_server";

/** Entry actor: internal user id + key fingerprint only (never provider ids). */
export interface ChainActor {
  readonly userId: string;
  readonly keyFingerprintHex: string;
}

export interface GenesisPayload {
  readonly encPubHex: string;
  readonly sigPubHex: string;
}

export interface AddMemberPayload {
  readonly targetUserId: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly role: Role;
}

export interface RemoveMemberPayload {
  readonly targetUserId: string;
}

export interface ChangeRolePayload {
  readonly targetUserId: string;
  readonly newRole: Role;
}

export interface RotateEpochPayload {
  readonly environmentId: string;
  readonly newEpoch: number;
  readonly reason: string;
}

export interface GrantServerPayload {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: string;
  /**
   * Environments the server key is granted access to. Canonicalized as a
   * nested length-prefixed encoding whose lowercase-hex form is one payload
   * field — list order is part of the signed bytes.
   */
  readonly scopeEnvironmentIds: readonly string[];
}

export interface RevokeServerPayload {
  readonly serverKeyFingerprintHex: string;
}

/** Operation + payload, discriminated by `op`. */
export type ChainOperation =
  | { readonly op: "genesis"; readonly payload: GenesisPayload }
  | { readonly op: "add_member"; readonly payload: AddMemberPayload }
  | { readonly op: "remove_member"; readonly payload: RemoveMemberPayload }
  | { readonly op: "change_role"; readonly payload: ChangeRolePayload }
  | { readonly op: "rotate_epoch"; readonly payload: RotateEpochPayload }
  | { readonly op: "grant_server"; readonly payload: GrantServerPayload }
  | { readonly op: "revoke_server"; readonly payload: RevokeServerPayload };

/** A chain entry before signing (CRYPTO_SPEC §6.1). */
export type UnsignedChainEntry = ChainOperation & {
  readonly suite: string;
  readonly seq: number;
  readonly prevHashHex: string;
  readonly actor: ChainActor;
  readonly timestampMs: number;
};

/** A complete signed chain entry (CRYPTO_SPEC §6.1). */
export type ChainEntry = UnsignedChainEntry & { readonly signatureHex: string };

/** A current member derived from a verified chain. */
export interface ChainMember {
  readonly userId: string;
  readonly role: Role;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly keyFingerprintHex: string;
}

/** An active server grant derived from a verified chain (CRYPTO_SPEC §9). */
export interface ServerGrant {
  readonly serverKeyFingerprintHex: string;
  readonly serverEncPubHex: string;
  readonly scopeEnvironmentIds: readonly string[];
}

/**
 * State derived from a verified chain (CRYPTO_SPEC §6.3): the current member
 * set (with roles), active server grants, and the epochs observed per
 * environment via rotate_epoch entries. This is the input for DEK-wrap
 * recipient checks and head gossip, implemented with the sync logic later.
 */
export interface ChainState {
  readonly members: ReadonlyMap<string, ChainMember>;
  readonly serverGrants: ReadonlyMap<string, ServerGrant>;
  readonly environmentEpochs: ReadonlyMap<string, number>;
  readonly headSeq: number;
  readonly headHashHex: string;
}
