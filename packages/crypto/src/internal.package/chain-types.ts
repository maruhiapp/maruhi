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
  | "create_environment"
  | "rotate_epoch"
  | "grant_server"
  | "revoke_server"
  | "checkpoint";

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

export interface CreateEnvironmentPayload {
  readonly environmentId: string;
  /**
   * Epoch-1 DEK commitment (CRYPTO_SPEC §5.2): lowercase hex, 64 chars.
   * Chain verification checks the format only — matching the commitment
   * against an unwrapped DEK is the recipient's §5.2 duty.
   */
  readonly dekCommitmentHex: string;
}

export interface RotateEpochPayload {
  readonly environmentId: string;
  /**
   * Strictly a number in this typed API. Wire formats (chain JSON, test
   * vectors) may carry the epoch as a decimal string — the §2.1 encoding
   * makes both forms byte-identical — but decoders MUST coerce to a number
   * before calling verifyChain; a string here is rejected as invalid-payload.
   */
  readonly newEpoch: number;
  readonly reason: string;
  /** New-epoch DEK commitment (CRYPTO_SPEC §5.2): lowercase hex, 64 chars. */
  readonly dekCommitmentHex: string;
}

/**
 * One exact-match claim constraint of a lease policy element (CRYPTO_SPEC
 * §6.2). v1 evaluation semantics (exact match only) live in AUTH_SPEC §14;
 * the chain consensus rules fix the structure only.
 */
export interface LeaseClaimConstraint {
  readonly claimName: string;
  readonly claimValue: string;
}

/**
 * One issuer element of a grant_server lease policy (CRYPTO_SPEC §6.2 /
 * §9.1): an issuer-generic workload identity federation constraint. All
 * claim constraints of an element must match (AND); any one element matching
 * authorizes the lease (existential — AUTH_SPEC §14-1).
 */
export interface LeasePolicyIssuer {
  readonly issuerUrl: string;
  readonly audience: string;
  readonly claimConstraints: readonly LeaseClaimConstraint[];
}

export interface GrantServerPayload {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: string;
  /**
   * Environments the server key is granted access to. Canonicalized as a
   * nested length-prefixed encoding whose lowercase-hex form is one payload
   * field — list order is part of the signed bytes.
   *
   * Re-granting the same server key may only widen the scope (old ⊆ new);
   * narrowing must go through revoke_server, which carries the §7 rotation
   * obligation.
   */
  readonly scopeEnvironmentIds: readonly string[];
  /**
   * Workload lease policy (CRYPTO_SPEC §6.2, 2026-08-12): the on-chain
   * authorization source for the §9.1 lease path. Canonicalized as a
   * three-level nested length-prefixed encoding whose lowercase-hex form is
   * the fourth payload field — element and constraint order are part of the
   * signed bytes. An empty list means "no lease path" (the grant only allows
   * server-directed wrap registration). Unlike the scope, a re-grant may
   * revise the lease policy freely (§6.3 — it is an ACL over the lease path
   * and does not change the set of DEKs the server already knows).
   */
  readonly leasePolicy: readonly LeasePolicyIssuer[];
}

export interface RevokeServerPayload {
  readonly serverKeyFingerprintHex: string;
}

/**
 * One environment tuple of a `checkpoint` payload (CRYPTO_SPEC §6.2): the
 * issuer's verified view of that environment — its current epoch (strict
 * equality with the entry-time chain-derived epoch is a consensus rule), the
 * latest manifest coordinates and the canonical values digest. The manifest
 * hash / values digest contents are not verifiable by chain verification
 * (they live in the data layer); acceptance-time content matching is the
 * server's §6.4 duty and distribution-time matching the client's §6.3 duty.
 */
export interface CheckpointEnvironmentEntry {
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  /** SHA-256 (lowercase hex) of the manifest's signed bytes (§4.3). */
  readonly manifestSigHashHex: string;
  /** Canonical env values digest (lowercase hex — §6.2 の values_digest). */
  readonly valuesDigestHex: string;
}

export interface CheckpointPayload {
  /**
   * Environment tuples — a subset of the active environments is valid
   * (§6.2: full coverage is an issuance SHOULD, not a consensus rule).
   * Duplicate environment ids make the payload invalid (structure check).
   * List order is part of the signed bytes; generation SHOULD sort by
   * environment id byte-ascending, verification does not normalize.
   */
  readonly environments: readonly CheckpointEnvironmentEntry[];
  /**
   * Server-attested audit-log rolling hash (AUDIT_SPEC §5.1), or the empty
   * string for "no audit-head attestation". A non-empty value requires the
   * actor to hold the admin role at this entry (consensus rule — §6.2).
   */
  readonly auditHeadHashHex: string;
}

/** Operation + payload, discriminated by `op`. */
export type ChainOperation =
  | { readonly op: "genesis"; readonly payload: GenesisPayload }
  | { readonly op: "add_member"; readonly payload: AddMemberPayload }
  | { readonly op: "remove_member"; readonly payload: RemoveMemberPayload }
  | { readonly op: "change_role"; readonly payload: ChangeRolePayload }
  | { readonly op: "create_environment"; readonly payload: CreateEnvironmentPayload }
  | { readonly op: "rotate_epoch"; readonly payload: RotateEpochPayload }
  | { readonly op: "grant_server"; readonly payload: GrantServerPayload }
  | { readonly op: "revoke_server"; readonly payload: RevokeServerPayload }
  | { readonly op: "checkpoint"; readonly payload: CheckpointPayload };

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
  /**
   * Seq of the `grant_server` entry that established this active grant — it
   * moves forward on a re-grant (CRYPTO_SPEC §6.3 の再 grant 二層規則). This
   * is the sole source of `server.lease_issued`'s `grant_chain_seq` (AUDIT_SPEC
   * §3.5): deriving it here keeps the re-grant rules in the chain verifier
   * rather than duplicating them in the server.
   */
  readonly grantSeq: number;
  readonly scopeEnvironmentIds: readonly string[];
  /** Lease policy of the latest accepted grant for this key (CRYPTO_SPEC §6.2). */
  readonly leasePolicy: readonly LeasePolicyIssuer[];
}

/**
 * One environment derived from a verified chain (CRYPTO_SPEC §6.2 / §6.3):
 * its existence (`create_environment`), the current epoch, the seq at which
 * each epoch became current (§6.3 の「各エポックの有効区間(開始 seq)」 —
 * §4.1 の値検証の入力), and the §5.2 DEK commitment per epoch.
 */
export interface EnvironmentChainState {
  readonly currentEpoch: number;
  /** Seq of the `create_environment` entry (= epoch 1's start seq). */
  readonly createdAtSeq: number;
  /** epoch → seq of the entry that made it current (create / rotate). */
  readonly epochStartSeqs: ReadonlyMap<number, number>;
  /** epoch → dek_commitment_hex (CRYPTO_SPEC §5.2). */
  readonly dekCommitments: ReadonlyMap<number, string>;
}

/**
 * The latest `checkpoint` tuple covering one environment, derived from a
 * verified chain (CRYPTO_SPEC §6.2 の検証状態 / §6.3 チェックポイント整合の
 * 環境ごとの基準). `seq` is the checkpoint entry that carried the tuple.
 */
export interface EnvironmentCheckpointState {
  readonly seq: number;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

/**
 * State derived from a verified chain (CRYPTO_SPEC §6.3): the current member
 * set (with roles), active server grants, and the environment set with per
 * epoch state. Environments exist only via `create_environment` (§6.2) —
 * there is no implicit "epoch defaults to 1" for unknown ids (2026-08-03).
 * This is the input for DEK-wrap recipient checks, the §5.2 commitment
 * matching, and head gossip (implemented with the sync logic later).
 */
export interface ChainState {
  readonly members: ReadonlyMap<string, ChainMember>;
  readonly serverGrants: ReadonlyMap<string, ServerGrant>;
  readonly environments: ReadonlyMap<string, EnvironmentChainState>;
  /**
   * Per environment, the latest `checkpoint` tuple covering it (§6.2 —
   * the `checkpoint-regression` baseline and the §6.3 checkpoint-integrity
   * baseline). Environments never covered by a checkpoint are absent.
   */
  readonly checkpoints: ReadonlyMap<string, EnvironmentCheckpointState>;
  readonly headSeq: number;
  readonly headHashHex: string;
}
