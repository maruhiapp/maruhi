// chain-entries.json のベクターを @maruhi/crypto の型付きエントリへ変換するヘルパ。

import type { ChainEntry, ChainOperation, Role } from "../../src/index.ts";
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
  readonly must_fail: boolean;
}

interface VectorValidAppend {
  readonly name: string;
  readonly entry: VectorEntry;
  readonly expected_members: Readonly<Record<string, string>>;
  readonly note?: string;
}

interface VectorHeadState {
  readonly after_seq: number;
  readonly members: Readonly<Record<string, string>>;
  readonly server_grants: readonly {
    readonly server_key_fingerprint_hex: string;
    readonly server_enc_pub_hex: string;
    readonly scope_environments: readonly string[];
  }[];
  readonly environment_epochs: Readonly<Record<string, string>>;
}

export const vectorEntries = chainVectors.entries as readonly VectorEntry[];
export const vectorNegatives = chainVectors.negative as readonly VectorNegative[];
export const vectorHeadStates = chainVectors.expected_head_states as readonly VectorHeadState[];
export const vectorValidAppends = chainVectors.valid_appends as readonly VectorValidAppend[];
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
    case "rotate_epoch":
      return {
        op,
        payload: {
          environmentId: str(payload, "environment_id"),
          newEpoch: Number(str(payload, "new_epoch")),
          reason: str(payload, "reason"),
        },
      };
    case "grant_server":
      return {
        op,
        payload: {
          serverEncPubHex: str(payload, "server_enc_pub_hex"),
          serverKeyFingerprintHex: str(payload, "server_key_fingerprint_hex"),
          scopeEnvironmentIds: payload["scope_environments"] as readonly string[],
        },
      };
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
