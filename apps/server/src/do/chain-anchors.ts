export interface CheckpointTuple {
  readonly seq: number;
  readonly entryHashHex: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

export const asRecord = (value: unknown): Record<string, unknown> | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

export const intField = (record: Record<string, unknown>, key: string): number | null => {
  const value = record[key];
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
};

export const strField = (record: Record<string, unknown>, key: string): string | null => {
  const value = record[key];
  return typeof value === "string" ? value : null;
};

const strArrayField = (record: Record<string, unknown>, key: string): readonly string[] | null => {
  const value = record[key];
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? (value as string[])
    : null;
};

export interface ChainRow {
  readonly seq: number;
  readonly entryJson: string;
  readonly entryHashHex: string | null;
}

export interface ChainAnchors {
  readonly headSeq: number;
  readonly hashBySeq: ReadonlyMap<number, string>;
  readonly epochStarts: ReadonlyMap<string, readonly (readonly [number, number])[]>;
  readonly deletedSeq: ReadonlyMap<string, number>;
  readonly rotateCounts: ReadonlyMap<string, number>;
  readonly addMemberSweeps: readonly {
    readonly seq: number;
    readonly targetUserId: string;
    readonly encPubHex: string;
  }[];
  readonly removedMembers: readonly { readonly seq: number; readonly targetUserId: string }[];
  readonly revokedDevices: readonly {
    readonly seq: number;
    readonly targetUserId: string;
    readonly fingerprints: readonly string[];
  }[];
  readonly tupleFor: ReadonlyMap<
    string,
    { readonly epoch: number; readonly sig: string } | "conflict"
  >;
  readonly latest: ReadonlyMap<string, CheckpointTuple>;
  readonly grantScopes: ReadonlyMap<number, readonly string[]>;
  readonly complete: boolean;
}

const ANCHORS_IGNORED_OPS: ReadonlySet<string> = new Set([
  "genesis",
  "change_role",
  "revoke_server",
  "set_approval_policy",
  "add_device",
  "withdraw",
]);

// fallow-ignore-next-line added-suppression -- deliberate: the checklist's complexity is inherent and reviewed unsplit; the next line states the function's own reason
// fallow-ignore-next-line complexity -- a per-op fold over the chain's entry taxonomy in seq order (the mirror of chain-history's recorder); the branches are the entry kinds the anchors are read from
export function foldChainAnchors(rows: Iterable<ChainRow>): ChainAnchors {
  const hashBySeq = new Map<number, string>();
  const epochStarts = new Map<string, [number, number][]>();
  const deletedSeq = new Map<string, number>();
  const rotateCounts = new Map<string, number>();
  const addMemberSweeps: { seq: number; targetUserId: string; encPubHex: string }[] = [];
  const removedMembers: { seq: number; targetUserId: string }[] = [];
  const revokedDevices: { seq: number; targetUserId: string; fingerprints: string[] }[] = [];
  const tupleFor = new Map<string, { readonly epoch: number; readonly sig: string } | "conflict">();
  const latest = new Map<string, CheckpointTuple>();
  const grantScopes = new Map<number, readonly string[]>();
  const proposedGrants = new Map<string, readonly string[]>();
  let headSeq = 0;
  let complete = true;
  for (const { seq, entryJson, entryHashHex } of rows) {
    if (entryHashHex !== null) {
      hashBySeq.set(seq, entryHashHex);
    }
    headSeq = Math.max(headSeq, seq);
    let parsed: unknown;
    try {
      parsed = JSON.parse(entryJson);
    } catch {
      complete = false;
      continue;
    }
    const entry = asRecord(parsed);
    const payload = entry === null ? null : asRecord(entry["payload"]);
    if (entry === null || payload === null) {
      complete = false;
      continue;
    }
    const op = strField(entry, "op");
    if (op === null) {
      complete = false;
      continue;
    }
    if (op === "create_environment" || op === "rotate_epoch" || op === "delete_environment") {
      const environmentId = strField(payload, "environmentId");
      if (environmentId === null) {
        complete = false;
        continue;
      }
      if (op === "create_environment") {
        epochStarts.set(environmentId, [[seq, 1]]);
      } else if (op === "rotate_epoch") {
        rotateCounts.set(environmentId, (rotateCounts.get(environmentId) ?? 0) + 1);
        const newEpoch = intField(payload, "newEpoch");
        if (newEpoch === null) {
          complete = false;
        }
        const starts = epochStarts.get(environmentId);
        if (starts === undefined) {
          complete = false;
        }
        if (newEpoch !== null && starts !== undefined) {
          starts.push([seq, newEpoch]);
        }
      } else if (!deletedSeq.has(environmentId)) {
        deletedSeq.set(environmentId, seq);
        latest.delete(environmentId);
      }
      continue;
    }
    if (op === "add_member" || op === "remove_member" || op === "revoke_device") {
      const targetUserId = strField(payload, "targetUserId");
      if (targetUserId === null) {
        complete = false;
        continue;
      }
      if (op === "add_member") {
        const encPubHex = strField(payload, "encPubHex");
        if (encPubHex === null) {
          complete = false;
        } else {
          addMemberSweeps.push({ seq, targetUserId, encPubHex });
        }
      } else if (op === "remove_member") {
        removedMembers.push({ seq, targetUserId });
      } else {
        const raw = payload["deviceFingerprintsHex"];
        const fingerprints = Array.isArray(raw)
          ? raw.filter((value): value is string => typeof value === "string")
          : [];
        if (!Array.isArray(raw) || fingerprints.length !== raw.length) {
          complete = false;
        }
        revokedDevices.push({ seq, targetUserId, fingerprints });
      }
      continue;
    }
    if (op === "grant_server") {
      const scope = strArrayField(payload, "scopeEnvironmentIds");
      if (scope !== null) {
        grantScopes.set(seq, scope);
      }
      continue;
    }
    if (op === "propose") {
      const inner = asRecord(payload["inner"]);
      const innerPayload = inner === null ? null : asRecord(inner["payload"]);
      if (inner !== null && innerPayload !== null && strField(inner, "op") === "grant_server") {
        const scope = strArrayField(innerPayload, "scopeEnvironmentIds");
        if (scope !== null && entryHashHex !== null) {
          proposedGrants.set(entryHashHex, scope);
        }
      }
      continue;
    }
    if (op === "approve") {
      const hash = strField(payload, "proposalHashHex");
      const scope = hash === null ? undefined : proposedGrants.get(hash);
      if (scope !== undefined) {
        grantScopes.set(seq, scope);
      }
      continue;
    }
    if (op !== "checkpoint") {
      if (!ANCHORS_IGNORED_OPS.has(op)) {
        complete = false;
      }
      continue;
    }
    if (!Array.isArray(payload["environments"]) || entryHashHex === null) {
      complete = false;
      continue;
    }
    for (const raw of payload["environments"]) {
      const tuple = asRecord(raw);
      if (tuple === null) {
        complete = false;
        continue;
      }
      const environmentId = strField(tuple, "environmentId");
      const epoch = intField(tuple, "epoch");
      const manifestVersion = intField(tuple, "manifestVersion");
      const manifestSigHashHex = strField(tuple, "manifestSigHashHex");
      const valuesDigestHex = strField(tuple, "valuesDigestHex");
      if (
        environmentId === null ||
        epoch === null ||
        manifestVersion === null ||
        manifestSigHashHex === null ||
        valuesDigestHex === null
      ) {
        complete = false;
        continue;
      }
      const deletedAt = deletedSeq.get(environmentId);
      if (deletedAt !== undefined && deletedAt < seq) {
        continue;
      }
      const key = `${environmentId}\n${manifestVersion}`;
      const existing = tupleFor.get(key);
      if (existing === undefined) {
        tupleFor.set(key, { epoch, sig: manifestSigHashHex });
      } else if (
        existing !== "conflict" &&
        (existing.epoch !== epoch || existing.sig !== manifestSigHashHex)
      ) {
        tupleFor.set(key, "conflict");
      }
      latest.set(environmentId, {
        seq,
        entryHashHex,
        epoch,
        manifestVersion,
        manifestSigHashHex,
        valuesDigestHex,
      });
    }
  }
  return {
    headSeq,
    hashBySeq,
    epochStarts,
    deletedSeq,
    rotateCounts,
    addMemberSweeps,
    removedMembers,
    revokedDevices,
    tupleFor,
    latest,
    grantScopes,
    complete,
  };
}

export function epochAt(
  anchors: ChainAnchors,
  environmentId: string,
  seq: number,
): number | undefined {
  const deletedAt = anchors.deletedSeq.get(environmentId);
  if (deletedAt !== undefined && deletedAt <= seq) {
    return undefined;
  }
  let epoch: number | undefined;
  for (const [fromSeq, value] of anchors.epochStarts.get(environmentId) ?? []) {
    if (fromSeq > seq) {
      break;
    }
    epoch = value;
  }
  return epoch;
}

export function checkpointRowsMatchLatest(
  rows: Iterable<Record<string, unknown>>,
  latest: ReadonlyMap<string, CheckpointTuple>,
): boolean {
  const seen = new Set<string>();
  for (const row of rows) {
    const environmentId = String(row["environment_id"]);
    seen.add(environmentId);
    const tuple = latest.get(environmentId);
    if (
      tuple === undefined ||
      Number(row["chain_seq"]) !== tuple.seq ||
      String(row["entry_hash_hex"]) !== tuple.entryHashHex ||
      Number(row["epoch"]) !== tuple.epoch ||
      Number(row["manifest_version"]) !== tuple.manifestVersion ||
      String(row["manifest_sig_hash_hex"]) !== tuple.manifestSigHashHex ||
      String(row["values_digest_hex"]) !== tuple.valuesDigestHex
    ) {
      return false;
    }
  }
  for (const environmentId of latest.keys()) {
    if (!seen.has(environmentId)) {
      return false;
    }
  }
  return true;
}
