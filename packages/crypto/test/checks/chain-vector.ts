// chain-entries.json のベクターを @maruhi/crypto の型付きエントリへ変換するヘルパ。

import type { ChainEntry, ChainOperation, Role, ServerGrant } from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };

export interface VectorEntry {
  readonly seq: number;
  readonly suite: string;
  readonly prev_hash_hex: string;
  readonly op: string;
  readonly actor: { readonly user_id: string; readonly key_fingerprint_hex: string };
  readonly payload: Readonly<Record<string, unknown>>;
  readonly timestamp_ms: number;
  readonly payload_bytes_hex: string;
  readonly signed_bytes_hex: string;
  readonly signature_hex: string;
  readonly entry_bytes_hex: string;
  readonly entry_hash_hex: string;
}

interface VectorNegative {
  readonly name: string;
  readonly kind?: string;
  readonly base_seq?: number;
  readonly payload?: Readonly<Record<string, unknown>>;
  readonly signed_bytes_hex?: string;
  readonly signature_hex?: string;
  readonly verify_key_hex?: string;
  readonly claimed_prev_hash_hex?: string;
  readonly expected_prev_hash_hex?: string;
  readonly entry?: VectorEntry;
  readonly expected_reason?: string;
  /** 認可 negative の前提チェーン(extended_chains のキー。無指定 = 正規チェーン)。 */
  readonly chain?: string;
  readonly must_fail: boolean;
}

/** grant_server payload / 導出状態の lease_policy のベクター表現(§6.2)。 */
interface VectorLeasePolicyIssuer {
  readonly issuer_url: string;
  readonly audience: string;
  readonly claim_constraints: readonly {
    readonly claim_name: string;
    readonly claim_value: string;
  }[];
}

interface VectorServerGrant {
  readonly server_key_fingerprint_hex: string;
  readonly server_enc_pub_hex: string;
  readonly scope_environments: readonly string[];
  readonly lease_policy: readonly VectorLeasePolicyIssuer[];
  /** 有効 grant を確立したエントリの seq(再 grant で前進 — §6.3 / AUDIT_SPEC §3.5)。 */
  readonly grant_seq: number;
}

interface VectorValidAppend {
  readonly name: string;
  readonly entry: VectorEntry;
  readonly expected_members: Readonly<Record<string, string>>;
  /** 受理後の環境ごとの現エポック(§6.2 環境ライフサイクル — 2026-08-03)。 */
  readonly expected_environments: Readonly<Record<string, string>>;
  /** 受理後の有効 grant 集合(§6.2 再 grant 二層 — 2026-08-12)。 */
  readonly expected_server_grants: readonly VectorServerGrant[];
  readonly note?: string;
}

/** 正規チェーンの途中ヘッドへ追記した派生チェーン(認可 negative の前提状態)。 */
interface VectorExtendedChain {
  readonly description: string;
  readonly base_seq: number;
  readonly entries: readonly VectorEntry[];
  readonly expected_members: Readonly<Record<string, string>>;
}

interface VectorEnvironmentState {
  readonly current_epoch: string;
  readonly created_at_seq: number;
  readonly epoch_start_seqs: Readonly<Record<string, number>>;
  readonly dek_commitments: Readonly<Record<string, string>>;
}

interface VectorHeadState {
  readonly after_seq: number;
  readonly members: Readonly<Record<string, string>>;
  readonly server_grants: readonly VectorServerGrant[];
  readonly environments: Readonly<Record<string, VectorEnvironmentState>>;
}

/**
 * 導出状態の有効 grant 集合がベクター期待(snake_case)と一致するか
 * (§6.2 — scope + lease_policy 込み。chain.ts / chain-negative.ts で共用)。
 */
export function serverGrantsMatchVector(
  serverGrants: ReadonlyMap<string, ServerGrant>,
  expected: readonly VectorServerGrant[],
): boolean {
  return (
    serverGrants.size === expected.length &&
    expected.every((grant) => {
      const actual = serverGrants.get(grant.server_key_fingerprint_hex);
      return (
        actual !== undefined &&
        actual.serverEncPubHex === grant.server_enc_pub_hex &&
        actual.grantSeq === grant.grant_seq &&
        actual.scopeEnvironmentIds.join(",") === grant.scope_environments.join(",") &&
        // lease_policy(§6.2)も導出状態の一部(順序込みで一致 — as-signed 順)
        JSON.stringify(
          actual.leasePolicy.map((element) => ({
            issuer_url: element.issuerUrl,
            audience: element.audience,
            claim_constraints: element.claimConstraints.map((constraint) => ({
              claim_name: constraint.claimName,
              claim_value: constraint.claimValue,
            })),
          })),
        ) === JSON.stringify(grant.lease_policy)
      );
    })
  );
}

export const vectorEntries = chainVectors.entries as readonly VectorEntry[];
export const vectorNegatives = chainVectors.negative as readonly VectorNegative[];
export const vectorHeadStates = chainVectors.expected_head_states as readonly VectorHeadState[];
export const vectorValidAppends = chainVectors.valid_appends as readonly VectorValidAppend[];
export const vectorExtendedChains = chainVectors.extended_chains as Readonly<
  Record<string, VectorExtendedChain>
>;
export const vectorKeys = chainVectors.keys as Readonly<
  Record<
    string,
    {
      readonly enc_sk_seed_hex: string;
      readonly sig_sk_seed_hex: string;
      readonly enc_pub_hex: string;
      readonly sig_pub_hex: string;
      readonly key_fingerprint_hex: string;
    }
  >
>;
/** 各 (environment, epoch) のダミー DEK と §5.2 コミットメント(実計算値)。 */
export const vectorEnvironmentDeks = chainVectors.environment_deks as Readonly<
  Record<
    string,
    Readonly<Record<string, { readonly dek_hex: string; readonly dek_commitment_hex: string }>>
  >
>;
function str(payload: Readonly<Record<string, unknown>>, key: string): string {
  const value = payload[key];
  if (typeof value !== "string") {
    throw new Error(`chain vector payload: expected string field ${key}`);
  }
  return value;
}

function toOperation(op: string, payload: Readonly<Record<string, unknown>>): ChainOperation {
  switch (op) {
    case "genesis":
      return {
        op,
        payload: { encPubHex: str(payload, "enc_pub_hex"), sigPubHex: str(payload, "sig_pub_hex") },
      };
    case "add_member":
      return {
        op,
        payload: {
          targetUserId: str(payload, "target_user_id"),
          encPubHex: str(payload, "enc_pub_hex"),
          sigPubHex: str(payload, "sig_pub_hex"),
          role: str(payload, "role") as Role,
        },
      };
    case "remove_member":
      return { op, payload: { targetUserId: str(payload, "target_user_id") } };
    case "change_role":
      return {
        op,
        payload: {
          targetUserId: str(payload, "target_user_id"),
          newRole: str(payload, "new_role") as Role,
        },
      };
    case "create_environment":
      return {
        op,
        payload: {
          environmentId: str(payload, "environment_id"),
          dekCommitmentHex: str(payload, "dek_commitment_hex"),
        },
      };
    case "rotate_epoch":
      return {
        op,
        payload: {
          environmentId: str(payload, "environment_id"),
          newEpoch: Number(str(payload, "new_epoch")),
          reason: str(payload, "reason"),
          dekCommitmentHex: str(payload, "dek_commitment_hex"),
        },
      };
    case "grant_server": {
      const leasePolicy = payload["lease_policy"] as readonly VectorLeasePolicyIssuer[];
      return {
        op,
        payload: {
          serverEncPubHex: str(payload, "server_enc_pub_hex"),
          serverKeyFingerprintHex: str(payload, "server_key_fingerprint_hex"),
          scopeEnvironmentIds: payload["scope_environments"] as readonly string[],
          leasePolicy: leasePolicy.map((element) => ({
            issuerUrl: element.issuer_url,
            audience: element.audience,
            claimConstraints: element.claim_constraints.map((constraint) => ({
              claimName: constraint.claim_name,
              claimValue: constraint.claim_value,
            })),
          })),
        },
      };
    }
    case "revoke_server":
      return {
        op,
        payload: { serverKeyFingerprintHex: str(payload, "server_key_fingerprint_hex") },
      };
    default:
      throw new Error(`chain vector: unknown op ${op}`);
  }
}

/** ベクターエントリを型付き ChainEntry へ変換する */
export function toTypedEntry(vector: VectorEntry): ChainEntry {
  return {
    ...toOperation(vector.op, vector.payload),
    suite: vector.suite,
    seq: vector.seq,
    prevHashHex: vector.prev_hash_hex,
    actor: {
      userId: vector.actor.user_id,
      keyFingerprintHex: vector.actor.key_fingerprint_hex,
    },
    timestampMs: vector.timestamp_ms,
    signatureHex: vector.signature_hex,
  };
}

export const typedEntries: readonly ChainEntry[] = vectorEntries.map(toTypedEntry);
