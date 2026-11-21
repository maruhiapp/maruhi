import {
  APPROVAL_TARGET_OPS,
  type ApprovalTargetOp,
  type ChainOperation,
  encodeLengthPrefixed,
  type LengthPrefixedField,
  verifyChain,
} from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };
import {
  toTypedEntry,
  type VectorEntry,
  vectorEntries,
  vectorExtendedChains,
  vectorValidAppends,
} from "./chain-vector.ts";
import { type CheckResult, Checks, toHex } from "./support.ts";

type ChainOpName = ChainOperation["op"];

const CHAIN_OPS: Record<ChainOpName, true> = {
  genesis: true,
  add_member: true,
  remove_member: true,
  change_role: true,
  create_environment: true,
  delete_environment: true,
  rotate_epoch: true,
  grant_server: true,
  revoke_server: true,
  checkpoint: true,
  set_approval_policy: true,
  propose: true,
  approve: true,
  withdraw: true,
  add_device: true,
  revoke_device: true,
};

const FOUR_EYES_TARGET_OPS: Record<ApprovalTargetOp, true> = {
  grant_server: true,
  revoke_server: true,
  remove_member: true,
  change_role: true,
  add_member: true,
  set_approval_policy: true,
};

const APPLIED_PROPOSAL_GAPS: Readonly<Partial<Record<ApprovalTargetOp, string>>> = {};

function keysOf<K extends string>(record: Readonly<Record<K, true>>): readonly K[] {
  return Object.keys(record) as unknown as readonly K[];
}

const fieldOrders = chainVectors.canonicalization.payload_field_order as Readonly<
  Record<string, readonly string[] | undefined>
>;

function encodeInFieldOrder(
  op: string,
  payload: Readonly<Record<string, unknown>>,
  order: readonly string[] | undefined = fieldOrders[op],
): Uint8Array | string {
  if (order === undefined) {
    return `no payload_field_order for ${op}`;
  }
  const fields: LengthPrefixedField[] = [];
  for (const field of order) {
    const value = payload[field];
    if (typeof value !== "string" && typeof value !== "number") {
      return `${op}.${field} is not a scalar payload field`;
    }
    fields.push(value);
  }
  return encodeLengthPrefixed(fields);
}

interface PositiveChain {
  readonly label: string;
  readonly entries: readonly VectorEntry[];
}

function positiveChains(): readonly PositiveChain[] {
  const extended = (name: string): readonly VectorEntry[] => {
    const chain = vectorExtendedChains[name];
    if (chain === undefined) {
      throw new Error(`chain vector extended chain ${name} missing`);
    }
    return [...vectorEntries.slice(0, chain.base_seq), ...chain.entries];
  };
  return [
    { label: "canonical", entries: vectorEntries },
    ...Object.keys(vectorExtendedChains).map((name) => ({
      label: `extended ${name}`,
      entries: extended(name),
    })),
    ...vectorValidAppends.map((append) => ({
      label: `valid append ${append.name}`,
      entries: [
        ...(append.chain === undefined
          ? vectorEntries.slice(0, append.entry.seq - 1)
          : extended(append.chain)),
        append.entry,
      ],
    })),
  ];
}

function positiveEntries(): readonly VectorEntry[] {
  const all = [
    ...vectorEntries,
    ...vectorValidAppends.map((append) => append.entry),
    ...Object.values(vectorExtendedChains).flatMap((chain) => chain.entries),
  ];
  return [...new Map(all.map((entry) => [entry.entry_hash_hex, entry])).values()];
}

function reencodeMismatch(
  op: string,
  payload: Readonly<Record<string, unknown>>,
  expectedHex: unknown,
): string | undefined {
  const bytes = encodeInFieldOrder(op, payload);
  if (typeof bytes === "string") {
    return bytes;
  }
  return toHex(bytes) === expectedHex ? undefined : "payload bytes differ";
}

function reencodeMismatches(entry: VectorEntry): readonly string[] {
  const label = `seq ${entry.seq} ${entry.op}`;
  const outer = reencodeMismatch(entry.op, entry.payload, entry.payload_bytes_hex);
  const found = outer === undefined ? [] : [`${label}: ${outer}`];
  if (entry.op !== "propose") {
    return found;
  }
  const innerOp = entry.payload["inner_op"];
  const innerPayload = entry.payload["inner_payload"];
  const inner =
    typeof innerOp === "string" && typeof innerPayload === "object" && innerPayload !== null
      ? reencodeMismatch(
          innerOp,
          innerPayload as Readonly<Record<string, unknown>>,
          entry.payload["inner_payload_lp_hex"],
        )
      : "inner op or payload missing";
  return inner === undefined ? found : [...found, `${label} inner: ${inner}`];
}

interface PayloadSample {
  readonly payload: Readonly<Record<string, unknown>>;
  readonly bytesHex: unknown;
}

function payloadSamples(entries: readonly VectorEntry[]): ReadonlyMap<string, PayloadSample[]> {
  const samples = new Map<string, PayloadSample[]>();
  const add = (op: string, sample: PayloadSample): void => {
    samples.set(op, [...(samples.get(op) ?? []), sample]);
  };
  for (const entry of entries) {
    add(entry.op, { payload: entry.payload, bytesHex: entry.payload_bytes_hex });
    const innerOp = entry.payload["inner_op"];
    const innerPayload = entry.payload["inner_payload"];
    if (entry.op === "propose" && typeof innerOp === "string" && typeof innerPayload === "object") {
      add(innerOp, {
        payload: innerPayload as Readonly<Record<string, unknown>>,
        bytesHex: entry.payload["inner_payload_lp_hex"],
      });
    }
  }
  return samples;
}

function swapped(order: readonly string[], i: number, j: number): readonly string[] {
  return order.map((field, k) => (k === i ? order[j]! : k === j ? order[i]! : field));
}

function unpinnedPairs(op: string, samples: readonly PayloadSample[]): readonly string[] {
  const order = fieldOrders[op] ?? [];
  const unpinned: string[] = [];
  for (let i = 0; i < order.length; i += 1) {
    for (let j = i + 1; j < order.length; j += 1) {
      const swap = swapped(order, i, j);
      const pinned = samples.some((sample) => {
        const bytes = encodeInFieldOrder(op, sample.payload, swap);
        return typeof bytes === "string" || toHex(bytes) !== sample.bytesHex;
      });
      if (!pinned) unpinned.push(`${op}: ${order[i]} / ${order[j]}`);
    }
  }
  return unpinned;
}

function fieldOrderPinnedChecks(c: Checks, entries: readonly VectorEntry[]): void {
  const samples = payloadSamples(entries);
  for (const op of keysOf(CHAIN_OPS)) {
    const unpinned = unpinnedPairs(op, samples.get(op) ?? []);
    c.push(
      `chain op coverage: ${op}'s payload_field_order is pinned (no field swap re-encodes every positive payload)`,
      unpinned.length === 0,
      unpinned.join("; "),
    );
  }
}

function fieldOrderChecks(c: Checks, entries: readonly VectorEntry[]): void {
  const ops = new Set<string>(keysOf(CHAIN_OPS));
  for (const op of keysOf(CHAIN_OPS)) {
    c.push(
      `chain op coverage: ${op} has a payload_field_order entry`,
      fieldOrders[op] !== undefined,
    );
  }
  const unknown = Object.keys(fieldOrders).filter((op) => !ops.has(op));
  c.push(
    "chain op coverage: payload_field_order names only ChainOperation ops",
    unknown.length === 0,
    `unknown: ${unknown.join(", ")}`,
  );
  const mismatches = entries.flatMap(reencodeMismatches);
  c.push(
    `chain op coverage: ${entries.length} positive payloads re-encode from payload_field_order`,
    mismatches.length === 0,
    mismatches.slice(0, 5).join("; "),
  );
}

function directCoverageChecks(c: Checks, entries: readonly VectorEntry[]): void {
  const exercised = new Set(entries.map((entry) => entry.op));
  for (const op of keysOf(CHAIN_OPS)) {
    c.push(`chain op coverage: ${op} is exercised by a positive vector`, exercised.has(op));
  }
}

async function appliedProposalOps(): Promise<ReadonlySet<string>> {
  const applied = new Set<string>();
  for (const chain of positiveChains()) {
    for (const [index, entry] of chain.entries.entries()) {
      const hash = entry.payload["proposal_hash_hex"];
      if (entry.op !== "approve" || typeof hash !== "string") {
        continue;
      }
      const proposal = chain.entries
        .slice(0, index)
        .find((candidate) => candidate.op === "propose" && candidate.entry_hash_hex === hash);
      const innerOp = proposal?.payload["inner_op"];
      if (typeof innerOp !== "string" || applied.has(innerOp)) {
        continue;
      }
      const result = await verifyChain(chain.entries.slice(0, index + 1).map(toTypedEntry));
      if (result.ok && !result.value.pendingProposals.has(hash)) {
        applied.add(innerOp);
      }
    }
  }
  return applied;
}

async function appliedProposalChecks(c: Checks): Promise<void> {
  const targets = keysOf(FOUR_EYES_TARGET_OPS);
  const declared = new Set<string>(APPROVAL_TARGET_OPS);
  c.push(
    "chain op coverage: four-eyes target record matches APPROVAL_TARGET_OPS",
    declared.size === targets.length && targets.every((op) => declared.has(op)),
  );
  const applied = await appliedProposalOps();
  for (const op of targets) {
    const gap = APPLIED_PROPOSAL_GAPS[op];
    if (gap === undefined) {
      c.push(`chain op coverage: ${op} is applied through an approved proposal`, applied.has(op));
    } else {
      c.push(
        `chain op coverage: ${op} applied-proposal gap is still open (pinned)`,
        !applied.has(op),
        `stale gap — a vector now applies ${op} through a proposal; remove it from APPLIED_PROPOSAL_GAPS`,
      );
    }
  }
}

export async function chainOpCoverageChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const entries = positiveEntries();
  fieldOrderChecks(c, entries);
  fieldOrderPinnedChecks(c, entries);
  directCoverageChecks(c, entries);
  await appliedProposalChecks(c);
  return c.results;
}
