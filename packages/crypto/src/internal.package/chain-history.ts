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
import { type MemberScope, scopeWithout } from "./member-scope.ts";

export interface MemberStateAtSeq {
  readonly role: Role;
  readonly scope: MemberScope;
  readonly devices: ReadonlyMap<string, ChainDevice>;
  readonly tenureStartSeq: number;
}

export interface DeviceStateAtSeq {
  readonly device: ChainDevice;
  readonly permission: EffectivePermission;
  readonly tenureStartSeq: number;
}

export type CheckpointTupleLookup =
  | {
      readonly kind: "unique";
      readonly seq: number;
      readonly epoch: number;
      readonly manifestSigHashHex: string;
    }
  | { readonly kind: "conflicting" };

export interface EnvironmentStateAtSeq {
  readonly createdAtSeq: number;
  readonly currentEpoch: number;
  readonly deletedAtSeq: number | null;
}

export interface ChainHistoryIndex {
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly entryHashAt: (seq: number) => string | undefined;
  readonly memberStateAt: (userId: string, seq: number) => MemberStateAtSeq | undefined;
  readonly deviceStateAt: (
    userId: string,
    keyFingerprintHex: string,
    seq: number,
  ) => DeviceStateAtSeq | undefined;
  readonly environmentStateAt: (
    environmentId: string,
    seq: number,
  ) => EnvironmentStateAtSeq | undefined;
  readonly sigKeyByFingerprint: (userId: string, keyFingerprintHex: string) => string | undefined;
  readonly checkpointTupleFor: (
    environmentId: string,
    manifestVersion: number,
  ) => CheckpointTupleLookup | undefined;
  readonly latestCheckpointFor: (environmentId: string) => EnvironmentCheckpointState | undefined;
}

interface MemberSpan {
  readonly fromSeq: number;
  readonly role: Role;
  readonly scope: MemberScope;
}

interface DeviceRecord {
  readonly device: ChainDevice;
  revokedSeq: number | null;
  readonly capChanges: { readonly fromSeq: number; readonly scope: MemberScope }[];
}

interface TenureRecord {
  readonly startSeq: number;
  endSeq: number | null;
  readonly devices: DeviceRecord[];
  readonly spans: MemberSpan[];
}

interface EnvironmentRecord {
  readonly createdAtSeq: number;
  readonly epochStarts: readonly (readonly [number, number])[];
  readonly deletedAtSeq: number | null;
}

type CheckpointTupleRecord =
  | {
      readonly seq: number;
      readonly epoch: number;
      readonly manifestSigHashHex: string;
    }
  | "conflict";

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

function deviceActiveAt(record: DeviceRecord, seq: number): boolean {
  return record.device.addedSeq <= seq && (record.revokedSeq === null || seq < record.revokedSeq);
}

function deviceAt(record: DeviceRecord, seq: number): ChainDevice {
  let scope = record.device.scope;
  for (const change of record.capChanges) {
    if (change.fromSeq <= seq) {
      scope = change.scope;
    } else {
      break;
    }
  }
  return scope === record.device.scope ? record.device : { ...record.device, scope };
}

function activeDevicesAt(tenure: TenureRecord, seq: number): ReadonlyMap<string, ChainDevice> {
  const devices = new Map<string, ChainDevice>();
  for (const record of tenure.devices) {
    if (deviceActiveAt(record, seq)) {
      devices.set(record.device.keyFingerprintHex, deviceAt(record, seq));
    }
  }
  return devices;
}

function epochAt(environment: EnvironmentRecord, seq: number): number | undefined {
  let currentEpoch: number | undefined;
  for (const [epoch, startSeq] of environment.epochStarts) {
    if (startSeq > seq) {
      break;
    }
    currentEpoch = epoch;
  }
  return currentEpoch;
}

function deletedAtOrBefore(environment: EnvironmentRecord, seq: number): number | null {
  const deletedAtSeq = environment.deletedAtSeq;
  return deletedAtSeq !== null && deletedAtSeq <= seq ? deletedAtSeq : null;
}

function pruneTenureAt(tenure: TenureRecord, environmentId: string, seq: number): void {
  const span = tenure.spans[tenure.spans.length - 1];
  if (span !== undefined) {
    const scope = scopeWithout(span.scope, environmentId);
    if (scope !== span.scope) {
      tenure.spans.push({ fromSeq: seq, role: span.role, scope });
    }
  }
  for (const record of tenure.devices) {
    const cap = deviceAt(record, seq).scope;
    const pruned = scopeWithout(cap, environmentId);
    if (record.revokedSeq === null && pruned !== cap) {
      record.capChanges.push({ fromSeq: seq, scope: pruned });
    }
  }
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
    const device = deviceAt(record, seq);
    return {
      device,
      permission: effectivePermissionOf(span, device),
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
    const currentEpoch = epochAt(environment, seq);
    if (currentEpoch === undefined) {
      return undefined;
    }
    return {
      createdAtSeq: environment.createdAtSeq,
      currentEpoch,
      deletedAtSeq: deletedAtOrBefore(environment, seq),
    };
  }

  sigKeyByFingerprint(userId: string, keyFingerprintHex: string): string | undefined {
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

export class ChainHistoryBuilder {
  readonly #entryHashes: string[] = [];
  readonly #tenures = new Map<string, TenureRecord[]>();
  readonly #environmentStarts = new Map<
    string,
    { createdAtSeq: number; epochStarts: [number, number][]; deletedAtSeq: number | null }
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
      devices: [{ device: firstDevice, revokedSeq: null, capChanges: [] }],
      spans: [{ fromSeq: startSeq, role, scope }],
    };
    const tenures = this.#tenures.get(userId);
    if (tenures === undefined) {
      this.#tenures.set(userId, [record]);
    } else {
      tenures.push(record);
    }
  }

  recordDeviceAdded(userId: string, device: ChainDevice): void {
    this.#openTenure(userId)?.devices.push({ device, revokedSeq: null, capChanges: [] });
  }

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
      deletedAtSeq: null,
    });
  }

  recordEnvironmentDeleted(environmentId: string, seq: number): void {
    const environment = this.#environmentStarts.get(environmentId);
    if (environment !== undefined) {
      environment.deletedAtSeq = seq;
    }
    this.#latestCheckpoints.delete(environmentId);
    for (const userId of this.#tenures.keys()) {
      const open = this.#openTenure(userId);
      if (open !== undefined) {
        pruneTenureAt(open, environmentId, seq);
      }
    }
  }

  recordEpochRotated(environmentId: string, newEpoch: number, seq: number): void {
    this.#environmentStarts.get(environmentId)?.epochStarts.push([newEpoch, seq]);
  }

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
