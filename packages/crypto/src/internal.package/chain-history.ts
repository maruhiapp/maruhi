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
// - change_role エントリ自身の seq で新 (role, scope) が有効(2026-09-14 ES —
//   履歴索引は在籍区間ごとに (role, scope) の変化点を保持する。§6.2 の検証状態)。
//   提案経由の適用(PF1)は定足数に達した approve エントリの seq が変化点
// - remove_member エントリ自身の seq で対象は無効
// - create_environment エントリ自身の seq でエポック 1 が有効
// - rotate_epoch エントリ自身の seq で新エポックが有効
// - add_device エントリ自身の seq で新端末は有効、revoke_device エントリ自身の seq で
//   その端末は無効(2026-09-19 DK — §6.2「端末の有効区間」。在籍区間の内側に端末ごとの
//   有効区間を持ち、remove_member は全端末を同時に終える)
//
// timestamp は認可判定に使わない(すべて seq ベース)。remove → re-add は別
// tenure として保持する(同じ鍵の dedupe で tenure を消さない — 裁定 A)。

import {
  type ChainDevice,
  type EffectivePermission,
  effectivePermissionOf,
} from "./chain-device.ts";
import type {
  CheckpointEnvironmentEntry,
  EnvironmentCheckpointState,
  Role,
} from "./chain-types.ts";
import type { MemberScope } from "./member-scope.ts";

/**
 * A member's chain-derived state at one inclusive seq (§6.3 の宣言ヘッド時点): the
 * person's (role, scope) and the devices active at that seq. There is no single
 * key field (2026-09-19 DK — 鍵は端末に属する): a signature's key is resolved with
 * `deviceStateAt`, and single-device callers use `soleDeviceOf`.
 */
export interface MemberStateAtSeq {
  readonly role: Role;
  /** Environment scope at that seq (§6.3 の 3′ — 宣言ヘッド時点の scope 検査の入力). */
  readonly scope: MemberScope;
  /** Devices active at that seq (inclusive intervals — §6.2), keyed by fingerprint. */
  readonly devices: ReadonlyMap<string, ChainDevice>;
  /** Seq of the genesis / add_member entry that started this tenure. */
  readonly tenureStartSeq: number;
}

/**
 * One device of a member at one inclusive seq (§6.3-1 の鍵選択 + 3 / 3′ の入力):
 * the device and the effective permission it held at that seq
 * (`effectivePermissionOf(person-at-seq, device)` — chain-device.ts).
 */
export interface DeviceStateAtSeq {
  readonly device: ChainDevice;
  readonly permission: EffectivePermission;
  /** Seq of the genesis / add_member entry that started the member's tenure. */
  readonly tenureStartSeq: number;
}

/**
 * Lookup result for the `checkpoint` tuple covering one
 * (environment_id, manifest_version) coordinate on the verified chain
 * (CRYPTO_SPEC §4.3 検証規則 (2) の照合材料).
 *
 * - `unique` — every checkpoint entry carrying this coordinate agrees on
 *   (epoch, manifest_sig_hash); `seq` is the first entry that carried it
 * - `conflicting` — two checkpoint entries carry this coordinate with a
 *   differing (epoch, manifest_sig_hash): hard evidence of manifest
 *   equivocation — the verifier must reject the environment's distribution
 *   (§4.3 (2)). The values digest is deliberately NOT part of this
 *   comparison: re-attesting the same manifest_version with a new values
 *   digest is a legitimate flow (rotate boundary checkpoint followed by the
 *   post-re-encryption periodic checkpoint — §6.3。session-33 裁定 B)
 */
export type CheckpointTupleLookup =
  | {
      readonly kind: "unique";
      readonly seq: number;
      readonly epoch: number;
      readonly manifestSigHashHex: string;
    }
  | { readonly kind: "conflicting" };

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
   * The device `keyFingerprintHex` of `userId` with `seq` applied inclusively —
   * the key the chain bound to the user at that point (§6.3-1: 端末の有効区間 =
   * add_device / add_member / genesis の seq から revoke_device の seq の直前まで) —
   * or undefined when the user is not a member at `seq` or the device is not
   * active at `seq` (never added, added later, revoked at or before `seq`, or
   * belonging to another tenure). The result carries the device's effective
   * permission at `seq` (§6.3-3 / -3′ の入力).
   */
  readonly deviceStateAt: (
    userId: string,
    keyFingerprintHex: string,
    seq: number,
  ) => DeviceStateAtSeq | undefined;
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
   * (userId, keyFingerprintHex) as any device of any tenure — the §6.3-1
   * candidate-key selection (head-time validity is `deviceStateAt`'s separate
   * check, so a cross-tenure or revoked key × head combination still gets its
   * signature verified first and is then rejected as `writer-key-mismatch-at-head`).
   */
  readonly sigKeyByFingerprint: (userId: string, keyFingerprintHex: string) => string | undefined;
  /**
   * The `checkpoint` tuple covering (environmentId, manifestVersion) anywhere
   * on the verified chain, or undefined when no checkpoint entry carries the
   * coordinate (§4.3 (2): the strict head-time epoch rule then applies). The
   * verifier consults this internally — the binding is not caller-supplied,
   * so a forgotten lookup cannot reopen the strict path for a coordinate the
   * chain has bound (session-33 裁定 A).
   */
  readonly checkpointTupleFor: (
    environmentId: string,
    manifestVersion: number,
  ) => CheckpointTupleLookup | undefined;
  /**
   * The latest checkpoint tuple covering the environment (§6.3
   * チェックポイント整合の環境ごとの基準 — mirror of
   * `ChainState.checkpoints` for history-based verifiers).
   */
  readonly latestCheckpointFor: (environmentId: string) => EnvironmentCheckpointState | undefined;
}

/** One (role, scope) span of a tenure — starts at `fromSeq` (inclusive). */
interface MemberSpan {
  readonly fromSeq: number;
  readonly role: Role;
  readonly scope: MemberScope;
}

/** One device's validity interval inside a tenure (§6.2 — [addedSeq, revokedSeq)). */
interface DeviceRecord {
  readonly device: ChainDevice;
  /** Seq of the revoke_device entry (device invalid at this seq — inclusive), or null while active. */
  revokedSeq: number | null;
}

interface TenureRecord {
  readonly startSeq: number;
  /** Seq of the remove_member entry (member invalid at this seq — inclusive). */
  endSeq: number | null;
  /** Devices in order of addition (the first is the genesis / add_member key). */
  readonly devices: DeviceRecord[];
  readonly spans: MemberSpan[];
}

interface EnvironmentRecord {
  readonly createdAtSeq: number;
  /** Ascending [epoch, startSeq] pairs (epoch 1 = createdAtSeq). */
  readonly epochStarts: readonly (readonly [number, number])[];
}

/** Per (environment, manifestVersion) checkpoint tuple, or a conflict marker. */
type CheckpointTupleRecord =
  | {
      readonly seq: number;
      readonly epoch: number;
      readonly manifestSigHashHex: string;
    }
  | "conflict";

/** change_role はエントリ自身の seq で新 (role, scope) が有効(inclusive)。 */
function spanAt(tenure: TenureRecord, seq: number): MemberSpan | undefined {
  let current: MemberSpan | undefined;
  for (const span of tenure.spans) {
    if (span.fromSeq <= seq) {
      current = span;
    } else {
      break;
    }
  }
  return current;
}

/** 端末は add_device の seq で有効・revoke_device の seq で無効(inclusive — §6.2)。 */
function deviceActiveAt(record: DeviceRecord, seq: number): boolean {
  return record.device.addedSeq <= seq && (record.revokedSeq === null || seq < record.revokedSeq);
}

function activeDevicesAt(tenure: TenureRecord, seq: number): ReadonlyMap<string, ChainDevice> {
  const devices = new Map<string, ChainDevice>();
  for (const record of tenure.devices) {
    if (deviceActiveAt(record, seq)) {
      devices.set(record.device.keyFingerprintHex, record.device);
    }
  }
  return devices;
}

class ChainHistory implements ChainHistoryIndex {
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly #entryHashes: readonly string[];
  readonly #tenures: ReadonlyMap<string, readonly TenureRecord[]>;
  readonly #environments: ReadonlyMap<string, EnvironmentRecord>;
  readonly #checkpointTuples: ReadonlyMap<string, ReadonlyMap<number, CheckpointTupleRecord>>;
  readonly #latestCheckpoints: ReadonlyMap<string, EnvironmentCheckpointState>;

  constructor(input: {
    readonly entryHashes: readonly string[];
    readonly tenures: ReadonlyMap<string, readonly TenureRecord[]>;
    readonly environments: ReadonlyMap<string, EnvironmentRecord>;
    readonly checkpointTuples: ReadonlyMap<string, ReadonlyMap<number, CheckpointTupleRecord>>;
    readonly latestCheckpoints: ReadonlyMap<string, EnvironmentCheckpointState>;
  }) {
    this.#entryHashes = input.entryHashes;
    this.#tenures = input.tenures;
    this.#environments = input.environments;
    this.#checkpointTuples = input.checkpointTuples;
    this.#latestCheckpoints = input.latestCheckpoints;
    this.headSeq = input.entryHashes.length;
    this.headHashHex = input.entryHashes[input.entryHashes.length - 1] ?? "";
  }

  entryHashAt(seq: number): string | undefined {
    if (!Number.isSafeInteger(seq) || seq < 1 || seq > this.headSeq) {
      return undefined;
    }
    return this.#entryHashes[seq - 1];
  }

  #tenureAt(userId: string, seq: number): TenureRecord | undefined {
    if (!Number.isSafeInteger(seq) || seq < 1 || seq > this.headSeq) {
      return undefined;
    }
    const tenures = this.#tenures.get(userId) ?? [];
    // remove は endSeq 自身で無効(inclusive)なので有効区間は [startSeq, endSeq)
    return tenures.find(
      (candidate) =>
        candidate.startSeq <= seq && (candidate.endSeq === null || seq < candidate.endSeq),
    );
  }

  memberStateAt(userId: string, seq: number): MemberStateAtSeq | undefined {
    const tenure = this.#tenureAt(userId, seq);
    if (tenure === undefined) {
      return undefined;
    }
    const span = spanAt(tenure, seq);
    if (span === undefined) {
      return undefined;
    }
    return {
      role: span.role,
      scope: span.scope,
      devices: activeDevicesAt(tenure, seq),
      tenureStartSeq: tenure.startSeq,
    };
  }

  deviceStateAt(
    userId: string,
    keyFingerprintHex: string,
    seq: number,
  ): DeviceStateAtSeq | undefined {
    const tenure = this.#tenureAt(userId, seq);
    if (tenure === undefined) {
      return undefined;
    }
    const span = spanAt(tenure, seq);
    const record = tenure.devices.find(
      (candidate) =>
        candidate.device.keyFingerprintHex === keyFingerprintHex && deviceActiveAt(candidate, seq),
    );
    if (span === undefined || record === undefined) {
      return undefined;
    }
    return {
      device: record.device,
      permission: effectivePermissionOf(span, record.device),
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
    // 全 tenure・全端末(失効済みを含む)から FP で選ぶ(§6.3-1 の鍵選択 — 有効区間の
    // 検査は deviceStateAt が署名検証の後に行う)。同じ FP は同じ鍵対なので、失効 →
    // 再登録で複数レコードに現れても sig 公開鍵は一致する
    for (const tenure of this.#tenures.get(userId) ?? []) {
      const record = tenure.devices.find(
        (candidate) => candidate.device.keyFingerprintHex === keyFingerprintHex,
      );
      if (record !== undefined) {
        return record.device.sigPubHex;
      }
    }
    return undefined;
  }

  checkpointTupleFor(
    environmentId: string,
    manifestVersion: number,
  ): CheckpointTupleLookup | undefined {
    if (!Number.isSafeInteger(manifestVersion) || manifestVersion < 1) {
      return undefined;
    }
    const record = this.#checkpointTuples.get(environmentId)?.get(manifestVersion);
    if (record === undefined) {
      return undefined;
    }
    if (record === "conflict") {
      return { kind: "conflicting" };
    }
    return {
      kind: "unique",
      seq: record.seq,
      epoch: record.epoch,
      manifestSigHashHex: record.manifestSigHashHex,
    };
  }

  latestCheckpointFor(environmentId: string): EnvironmentCheckpointState | undefined {
    return this.#latestCheckpoints.get(environmentId);
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
  readonly #checkpointTuples = new Map<string, Map<number, CheckpointTupleRecord>>();
  readonly #latestCheckpoints = new Map<string, EnvironmentCheckpointState>();

  recordEntryHash(hash: string): void {
    this.#entryHashes.push(hash);
  }

  #openTenure(userId: string): TenureRecord | undefined {
    const tenures = this.#tenures.get(userId);
    const last = tenures?.[tenures.length - 1];
    return last !== undefined && last.endSeq === null ? last : undefined;
  }

  /**
   * genesis / add_member: a tenure starts at `startSeq` with its first device
   * (structural cap (owner, all) — §6.2; `firstDevice.addedSeq` must equal `startSeq`).
   */
  recordTenureStart(
    userId: string,
    startSeq: number,
    firstDevice: ChainDevice,
    role: Role,
    scope: MemberScope,
  ): void {
    const record: TenureRecord = {
      startSeq,
      endSeq: null,
      devices: [{ device: firstDevice, revokedSeq: null }],
      spans: [{ fromSeq: startSeq, role, scope }],
    };
    const tenures = this.#tenures.get(userId);
    if (tenures === undefined) {
      this.#tenures.set(userId, [record]);
    } else {
      tenures.push(record);
    }
  }

  /** add_device: the device is active from `device.addedSeq` (inclusive — §6.2). */
  recordDeviceAdded(userId: string, device: ChainDevice): void {
    this.#openTenure(userId)?.devices.push({ device, revokedSeq: null });
  }

  /** revoke_device: each listed active device is invalid from `seq` (inclusive — §6.2). */
  recordDevicesRevoked(userId: string, seq: number, keyFingerprintsHex: readonly string[]): void {
    const open = this.#openTenure(userId);
    if (open === undefined) {
      return;
    }
    const revoked = new Set(keyFingerprintsHex);
    for (const record of open.devices) {
      if (record.revokedSeq === null && revoked.has(record.device.keyFingerprintHex)) {
        record.revokedSeq = seq;
      }
    }
  }

  /** change_role: the new (role, scope) pair is current from `seq` (inclusive — §6.2 の全置換). */
  recordRoleChange(userId: string, seq: number, role: Role, scope: MemberScope): void {
    this.#openTenure(userId)?.spans.push({ fromSeq: seq, role, scope });
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

  /**
   * checkpoint エントリの環境タプルを記録する(§6.2 の導出状態 / §4.3 (2) の
   * 照合材料)。同一 (environment, manifestVersion) に (epoch, manifest_sig_hash)
   * の異なるタプルが現れたら conflict へ格下げする(equivocation の証拠化 —
   * session-33 裁定 B。values_digest は同一 mv でも正当に変わるため比較対象外)。
   */
  recordCheckpoint(seq: number, environments: readonly CheckpointEnvironmentEntry[]): void {
    for (const tuple of environments) {
      let perEnv = this.#checkpointTuples.get(tuple.environmentId);
      if (perEnv === undefined) {
        perEnv = new Map();
        this.#checkpointTuples.set(tuple.environmentId, perEnv);
      }
      const existing = perEnv.get(tuple.manifestVersion);
      if (existing === undefined) {
        perEnv.set(tuple.manifestVersion, {
          seq,
          epoch: tuple.epoch,
          manifestSigHashHex: tuple.manifestSigHashHex,
        });
      } else if (
        existing !== "conflict" &&
        (existing.epoch !== tuple.epoch || existing.manifestSigHashHex !== tuple.manifestSigHashHex)
      ) {
        perEnv.set(tuple.manifestVersion, "conflict");
      }
      this.#latestCheckpoints.set(tuple.environmentId, {
        seq,
        epoch: tuple.epoch,
        manifestVersion: tuple.manifestVersion,
        manifestSigHashHex: tuple.manifestSigHashHex,
        valuesDigestHex: tuple.valuesDigestHex,
      });
    }
  }

  build(): ChainHistoryIndex {
    return new ChainHistory({
      entryHashes: this.#entryHashes,
      tenures: this.#tenures,
      environments: this.#environmentStarts,
      checkpointTuples: this.#checkpointTuples,
      latestCheckpoints: this.#latestCheckpoints,
    });
  }
}
