// CRYPTO_SPEC §6.3 / §4.1: 検証済みチェーンの履歴索引(ChainHistoryIndex)。
//
// 値署名の検証(value-verify.ts)は「宣言ヘッド時点」(inclusive)のチェーン
// 導出状態を要する。値ごとにチェーン全体を再署名検証するのは過大なので、
// verifyChainWithHistory(chain-verify.ts)が検証ループと同時に本索引を一度
// 構築し、server / CLI は検証済み snapshot ごとにこれを照会する(session-14
// 裁定 A: 最終 ChainState や単純な keyHistory では tenure・時点照会を表せない)。
//
// inclusive 規約(§6.3。ベクター value-signature.json が固定):
// - genesis / add_member エントリ自身の seq で対象メンバーは有効
// - change_role エントリ自身の seq で新 role が有効
// - remove_member エントリ自身の seq で対象は無効
// - create_environment エントリ自身の seq でエポック 1 が有効
// - rotate_epoch エントリ自身の seq で新エポックが有効
//
// timestamp は認可判定に使わない(すべて seq ベース)。remove → re-add は別
// tenure として保持する(同じ鍵の dedupe で tenure を消さない — 裁定 A)。

import type { Role } from "./chain-types.ts";

/** A member's chain-derived state at one inclusive seq (§6.3 の宣言ヘッド時点). */
export interface MemberStateAtSeq {
  readonly role: Role;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly keyFingerprintHex: string;
  /** Seq of the genesis / add_member entry that started this tenure. */
  readonly tenureStartSeq: number;
}

/** An environment's chain-derived state at one inclusive seq (§6.3-4 の入力). */
export interface EnvironmentStateAtSeq {
  /** Seq of the `create_environment` entry. */
  readonly createdAtSeq: number;
  /** The epoch current at the queried seq (epoch N is current from its start seq). */
  readonly currentEpoch: number;
}

/**
 * History queries over one fully verified chain snapshot (CRYPTO_SPEC §6.3).
 * Obtainable only through `verifyChainWithHistory` — an index never exists
 * for an unverified chain.
 */
export interface ChainHistoryIndex {
  readonly headSeq: number;
  readonly headHashHex: string;
  /** Entry hash at `seq` (1-based), or undefined beyond the head. */
  readonly entryHashAt: (seq: number) => string | undefined;
  /**
   * The member state of `userId` with `seq` applied inclusively, or
   * undefined when the user is not a member at that point (never a member,
   * removed at or before `seq`, or re-added only after `seq`).
   */
  readonly memberStateAt: (userId: string, seq: number) => MemberStateAtSeq | undefined;
  /**
   * The environment state with `seq` applied inclusively, or undefined when
   * the environment's `create_environment` has not occurred by `seq`.
   */
  readonly environmentStateAt: (
    environmentId: string,
    seq: number,
  ) => EnvironmentStateAtSeq | undefined;
  /**
   * The sig public key (lowercase hex) the chain history binds to
   * (userId, keyFingerprintHex) in any tenure — the §6.3-1 candidate-key
   * selection (head-time validity is `memberStateAt`'s separate check, so a
   * cross-tenure key × head combination still gets its signature verified
   * first and is then rejected as `writer-key-mismatch-at-head`).
   */
  readonly sigKeyByFingerprint: (userId: string, keyFingerprintHex: string) => string | undefined;
}

interface RoleSpan {
  readonly fromSeq: number;
  readonly role: Role;
}

interface TenureRecord {
  readonly startSeq: number;
  /** Seq of the remove_member entry (member invalid at this seq — inclusive). */
  endSeq: number | null;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly keyFingerprintHex: string;
  readonly roles: RoleSpan[];
}

interface EnvironmentRecord {
  readonly createdAtSeq: number;
  /** Ascending [epoch, startSeq] pairs (epoch 1 = createdAtSeq). */
  readonly epochStarts: readonly (readonly [number, number])[];
}

class ChainHistory implements ChainHistoryIndex {
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly #entryHashes: readonly string[];
  readonly #tenures: ReadonlyMap<string, readonly TenureRecord[]>;
  readonly #environments: ReadonlyMap<string, EnvironmentRecord>;

  constructor(input: {
    readonly entryHashes: readonly string[];
    readonly tenures: ReadonlyMap<string, readonly TenureRecord[]>;
    readonly environments: ReadonlyMap<string, EnvironmentRecord>;
  }) {
    this.#entryHashes = input.entryHashes;
    this.#tenures = input.tenures;
    this.#environments = input.environments;
    this.headSeq = input.entryHashes.length;
    this.headHashHex = input.entryHashes[input.entryHashes.length - 1] ?? "";
  }

  entryHashAt(seq: number): string | undefined {
    if (!Number.isSafeInteger(seq) || seq < 1 || seq > this.headSeq) {
      return undefined;
    }
    return this.#entryHashes[seq - 1];
  }

  memberStateAt(userId: string, seq: number): MemberStateAtSeq | undefined {
    if (!Number.isSafeInteger(seq) || seq < 1 || seq > this.headSeq) {
      return undefined;
    }
    const tenures = this.#tenures.get(userId) ?? [];
    // remove は endSeq 自身で無効(inclusive)なので有効区間は [startSeq, endSeq)
    const tenure = tenures.find(
      (candidate) =>
        candidate.startSeq <= seq && (candidate.endSeq === null || seq < candidate.endSeq),
    );
    if (tenure === undefined) {
      return undefined;
    }
    // change_role はエントリ自身の seq で新 role が有効(inclusive)
    let role = tenure.roles[0]?.role;
    for (const span of tenure.roles) {
      if (span.fromSeq <= seq) {
        role = span.role;
      } else {
        break;
      }
    }
    if (role === undefined) {
      return undefined;
    }
    return {
      role,
      encPubHex: tenure.encPubHex,
      sigPubHex: tenure.sigPubHex,
      keyFingerprintHex: tenure.keyFingerprintHex,
      tenureStartSeq: tenure.startSeq,
    };
  }

  environmentStateAt(environmentId: string, seq: number): EnvironmentStateAtSeq | undefined {
    if (!Number.isSafeInteger(seq) || seq < 1 || seq > this.headSeq) {
      return undefined;
    }
    const environment = this.#environments.get(environmentId);
    if (environment === undefined || seq < environment.createdAtSeq) {
      return undefined;
    }
    let currentEpoch: number | undefined;
    for (const [epoch, startSeq] of environment.epochStarts) {
      if (startSeq <= seq) {
        currentEpoch = epoch;
      } else {
        break;
      }
    }
    if (currentEpoch === undefined) {
      return undefined;
    }
    return { createdAtSeq: environment.createdAtSeq, currentEpoch };
  }

  sigKeyByFingerprint(userId: string, keyFingerprintHex: string): string | undefined {
    const tenures = this.#tenures.get(userId) ?? [];
    return tenures.find((tenure) => tenure.keyFingerprintHex === keyFingerprintHex)?.sigPubHex;
  }
}

/**
 * Mutable recorder driven by the verifyChain loop (chain-verify.ts). Not part
 * of the package's public surface — indexes are only handed out for chains
 * that passed full verification.
 */
export class ChainHistoryBuilder {
  readonly #entryHashes: string[] = [];
  readonly #tenures = new Map<string, TenureRecord[]>();
  readonly #environmentStarts = new Map<
    string,
    { createdAtSeq: number; epochStarts: [number, number][] }
  >();

  recordEntryHash(hash: string): void {
    this.#entryHashes.push(hash);
  }

  #openTenure(userId: string): TenureRecord | undefined {
    const tenures = this.#tenures.get(userId);
    const last = tenures?.[tenures.length - 1];
    return last !== undefined && last.endSeq === null ? last : undefined;
  }

  recordTenureStart(
    userId: string,
    startSeq: number,
    keys: { readonly encPubHex: string; readonly sigPubHex: string },
    keyFingerprintHex: string,
    role: Role,
  ): void {
    const record: TenureRecord = {
      startSeq,
      endSeq: null,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      keyFingerprintHex,
      roles: [{ fromSeq: startSeq, role }],
    };
    const tenures = this.#tenures.get(userId);
    if (tenures === undefined) {
      this.#tenures.set(userId, [record]);
    } else {
      tenures.push(record);
    }
  }

  recordRoleChange(userId: string, seq: number, role: Role): void {
    this.#openTenure(userId)?.roles.push({ fromSeq: seq, role });
  }

  recordTenureEnd(userId: string, seq: number): void {
    const open = this.#openTenure(userId);
    if (open !== undefined) {
      open.endSeq = seq;
    }
  }

  recordEnvironmentCreated(environmentId: string, seq: number): void {
    this.#environmentStarts.set(environmentId, {
      createdAtSeq: seq,
      epochStarts: [[1, seq]],
    });
  }

  recordEpochRotated(environmentId: string, newEpoch: number, seq: number): void {
    this.#environmentStarts.get(environmentId)?.epochStarts.push([newEpoch, seq]);
  }

  build(): ChainHistoryIndex {
    return new ChainHistory({
      entryHashes: this.#entryHashes,
      tenures: this.#tenures,
      environments: this.#environmentStarts,
    });
  }
}
