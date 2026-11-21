import type { AuditEventRecord } from "@maruhi/core";
import {
  assertProjectAuditPayload,
  auditPayloadWith,
  CHAIN_MIRROR_EVENT_PREFIX,
  cryptoEffect,
} from "@maruhi/core";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import { Context, Data, Effect, Layer } from "effect";

import type { AuditEventsQuery, StoredAuditEventRow } from "./audit-store-query.ts";
import { queryEvents } from "./audit-store-query.ts";
import type { AuditRotationRead } from "./audit-store-rotation-read.ts";
import { makeRotationRead } from "./audit-store-rotation-read.ts";
import { AUDIT_ROW_COLUMNS, toAuditHeadRow } from "./audit-store-rows.ts";
import { randomHexSync } from "./ids.ts";
import { ServerLoggerLive } from "./server-logger.ts";

export type AuditEventInput = AuditEventRecord;

export type AuditHeadExtensionOutcome = "current" | "more-remains";

interface AuditStoreShape {
  readonly appendSync: (event: AuditEventInput) => void;
  readonly appendManySync: (events: readonly AuditEventInput[]) => void;
  readonly resetSeqCacheSync: () => void;
  readonly readRotationSync: AuditRotationRead;
  readonly queryEventsSync: (query: AuditEventsQuery) => readonly StoredAuditEventRow[];
  readonly ensureHeadCurrent: Effect.Effect<AuditHeadExtensionOutcome>;
  readonly headColumnBehindSync: () => boolean;
  readonly currentHeadHexSync: () => string;
  readonly headPositionSync: (headHashHex: string) => number | null;
  readonly latestCheckpointMirrorSeqSync: () => number | null;
}

export class AuditStore extends Context.Service<AuditStore, AuditStoreShape>()("AuditStore") {}

const INSERT_COLUMNS = `INSERT INTO audit_events (
    seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id,
    actor_key_fingerprint, actor_api_token_id, target_user_id,
    target_key_fingerprint, environment_id, variable_id, epoch, version,
    chain_seq, payload
  ) VALUES `;

const VALUES_ROW = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

const APPEND_CHUNK_ROWS = 5;

function orNull(value: string | number | undefined): string | number | null {
  return value === undefined ? null : value;
}

function assertChainSeqInvariant(event: AuditEventInput): void {
  if (event.chainSeq !== undefined && !event.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
    throw new Error("audit invariant violation: chain_seq is reserved for chain.* events");
  }
}

function assertAppendable(event: AuditEventInput): void {
  assertChainSeqInvariant(event);
  assertProjectAuditPayload(event);
}

function storedPayload(event: AuditEventInput): string | null {
  const payload = auditPayloadWith(
    event.actorAuthMethod === undefined ? {} : { authMethod: event.actorAuthMethod },
    event.payload,
  );
  return Object.keys(payload).length === 0 ? null : JSON.stringify(payload);
}

function eventBindings(event: AuditEventInput): (string | number | null)[] {
  return [
    event.serverTs,
    orNull(event.clientTs),
    event.event,
    event.actorType,
    orNull(event.actorUserId),
    orNull(event.actorKeyFingerprintHex),
    orNull(event.actorApiTokenId),
    orNull(event.targetUserId),
    orNull(event.targetKeyFingerprintHex),
    orNull(event.environmentId),
    orNull(event.variableId),
    orNull(event.epoch),
    orNull(event.version),
    orNull(event.chainSeq),
    storedPayload(event),
  ];
}

export interface AuditStoreOptions {
  readonly maxHeadExtensionChunks?: number;
}

export const makeAuditStore = (sql: SqlStorage, options?: AuditStoreOptions): AuditStoreShape => {
  let nextSeqCache: number | null = null;
  const nextSeq = (): number => {
    if (nextSeqCache === null) {
      const row = sql
        .exec("SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM audit_events")
        .toArray()[0];
      nextSeqCache = Number(row?.["next_seq"] ?? 1);
    }
    return nextSeqCache;
  };
  return {
    appendSync: (event) => {
      assertAppendable(event);
      const seq = nextSeq();
      try {
        sql.exec(INSERT_COLUMNS + VALUES_ROW, seq, randomHexSync(16), ...eventBindings(event));
      } catch (error) {
        nextSeqCache = null;
        throw error;
      }
      nextSeqCache = seq + 1;
    },
    appendManySync: (events) => {
      for (const event of events) {
        assertAppendable(event);
      }
      try {
        for (let offset = 0; offset < events.length; offset += APPEND_CHUNK_ROWS) {
          const chunk = events.slice(offset, offset + APPEND_CHUNK_ROWS);
          const seq = nextSeq();
          sql.exec(
            INSERT_COLUMNS + chunk.map(() => VALUES_ROW).join(", "),
            ...chunk.flatMap((event, index) => [
              seq + index,
              randomHexSync(16),
              ...eventBindings(event),
            ]),
          );
          nextSeqCache = seq + chunk.length;
        }
      } catch (error) {
        nextSeqCache = null;
        throw error;
      }
    },
    resetSeqCacheSync: () => {
      nextSeqCache = null;
    },
    readRotationSync: makeRotationRead(sql),
    queryEventsSync: (query) => queryEvents(sql, query),
    ensureHeadCurrent: extendHeadHashes(
      sql,
      options?.maxHeadExtensionChunks ?? MAX_HEAD_EXTENSION_CHUNKS_PER_CALL,
    ),
    headColumnBehindSync: () => {
      const row = sql
        .exec(
          `SELECT 1 FROM audit_events
           WHERE seq > (SELECT COALESCE(MAX(seq), 0) FROM audit_head_hashes)
           LIMIT 1`,
        )
        .toArray()[0];
      return row !== undefined;
    },
    currentHeadHexSync: () => {
      const row = sql
        .exec("SELECT head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1")
        .toArray()[0];
      return row === undefined ? "" : String(row["head_hash_hex"]);
    },
    headPositionSync: (headHashHex) => {
      const row = sql
        .exec("SELECT seq FROM audit_head_hashes WHERE head_hash_hex = ? LIMIT 1", headHashHex)
        .toArray()[0];
      return row === undefined ? null : Number(row["seq"]);
    },
    latestCheckpointMirrorSeqSync: () => {
      const row = sql
        .exec("SELECT MAX(seq) AS seq FROM audit_events WHERE event = 'chain.checkpointed'")
        .toArray()[0];
      return row === undefined || row["seq"] === null ? null : Number(row["seq"]);
    },
  };
};

const HEAD_CHUNK_ROWS = 50;

export const MAX_HEAD_EXTENSION_CHUNKS_PER_CALL = 200;

const extendHeadHashes = Effect.fn("audit-store.extendHeadHashes")(function* (
  sql: SqlStorage,
  maxChunks: number,
): Effect.fn.Return<AuditHeadExtensionOutcome> {
  const state = { hashedUpTo: 0, head: "" };
  const tail = sql
    .exec(`SELECT seq, head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1`)
    .toArray()[0];
  if (tail !== undefined) {
    state.hashedUpTo = Number(tail["seq"]);
    state.head = String(tail["head_hash_hex"]);
  }
  for (let chunk = 0; chunk < maxChunks; chunk += 1) {
    if (yield* hashNextChunk(sql, state)) {
      return "current";
    }
  }
  const remains = sql
    .exec(`SELECT 1 FROM audit_events WHERE seq > ? LIMIT 1`, state.hashedUpTo)
    .toArray()[0];
  return remains === undefined ? "current" : "more-remains";
});

const hashNextChunk = (
  sql: SqlStorage,
  state: { hashedUpTo: number; head: string },
): Effect.Effect<boolean> =>
  deriveChunk(sql, "audit_events", "audit_head_hashes", state, true).pipe(
    Effect.map((outcome) => outcome === "done"),
    Effect.catchTag("AuditHeadChunkInvalid", (error) =>
      Effect.die(new Error(`audit log cannot be hashed at seq ${error.seq}: ${error.reason}`)),
    ),
  );

class AuditHeadChunkInvalidError extends Data.TaggedError("AuditHeadChunkInvalid")<{
  readonly seq: number;
  readonly reason: string;
}> {}

const deriveChunk = Effect.fnUntraced(function* (
  sql: SqlStorage,
  source: string,
  target: string,
  state: { hashedUpTo: number; head: string },
  persist: boolean,
): Effect.fn.Return<"done" | "more", AuditHeadChunkInvalidError> {
  const rows = sql
    .exec(
      `SELECT ${AUDIT_ROW_COLUMNS} FROM ${source} WHERE seq > ? ORDER BY seq LIMIT ?`,
      state.hashedUpTo,
      HEAD_CHUNK_ROWS,
    )
    .toArray()
    .map(toAuditHeadRow);
  if (rows.length === 0) {
    return "done";
  }
  const inserts: (string | number)[] = [];
  for (const row of rows) {
    if (row.seq !== state.hashedUpTo + 1) {
      return yield* new AuditHeadChunkInvalidError({
        seq: state.hashedUpTo + 1,
        reason: "seq gap",
      });
    }
    const digest = yield* cryptoEffect(() => computeAuditRowDigest(row)).pipe(
      Effect.mapError(
        (error) =>
          new AuditHeadChunkInvalidError({
            seq: row.seq,
            reason: `row digest: ${error["_tag"]}`,
          }),
      ),
    );
    const next = yield* cryptoEffect(() =>
      computeAuditHeadHash(SUITE_ID, state.head, row.seq, digest),
    ).pipe(
      Effect.mapError(
        (error) =>
          new AuditHeadChunkInvalidError({
            seq: row.seq,
            reason: `head hash: ${error["_tag"]}`,
          }),
      ),
    );
    state.head = next;
    state.hashedUpTo = row.seq;
    inserts.push(row.seq, state.head);
  }
  if (persist) {
    sql.exec(
      `INSERT INTO ${target} (seq, head_hash_hex) VALUES ${rows.map(() => "(?, ?)").join(", ")}`,
      ...inserts,
    );
  }
  return rows.length < HEAD_CHUNK_ROWS ? "done" : "more";
});

export function isAuditHeadHex(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

export async function deriveAuditHeads(
  sql: SqlStorage,
  source: string,
  target: string,
  fromSeq: number,
  prevHead: string,
  stores: () => boolean = () => true,
): Promise<string | null> {
  const state = { hashedUpTo: fromSeq, head: prevHead };
  let persist = true;
  for (;;) {
    persist = persist && stores();
    const outcome = await Effect.runPromise(
      deriveChunk(sql, source, target, state, persist).pipe(
        Effect.catchTag("AuditHeadChunkInvalid", () => Effect.succeed("invalid" as const)),
        Effect.provide(ServerLoggerLive),
      ),
    );
    if (outcome !== "more") {
      return outcome === "done" ? state.head : null;
    }
  }
}

export function auditRowShapeViolations(sql: SqlStorage, table: string): number {
  return Number(
    sql
      .exec(
        `SELECT COUNT(*) AS n FROM ${table} WHERE ${notCounting("seq")} OR seq < 1 OR ${notCounting("server_ts")} OR ${nullableNotCounting("client_ts")} OR ${nullableNotCounting("epoch")} OR ${nullableNotCounting("version")} OR ${nullableNotCounting("chain_seq")} OR ${notFingerprint("actor_key_fingerprint")} OR ${notFingerprint("target_key_fingerprint")}`,
      )
      .one()["n"],
  );
}

function notCounting(column: string): string {
  return `(typeof(${column}) <> 'integer' OR ${column} < 0 OR ${column} > 9007199254740991)`;
}

function nullableNotCounting(column: string): string {
  return `(${column} IS NOT NULL AND ${notCounting(column)})`;
}

function notFingerprint(column: string): string {
  return `(${column} IS NOT NULL AND (typeof(${column}) <> 'text' OR length(${column}) <> 32 OR ${column} GLOB '*[^0-9a-f]*'))`;
}

export const auditStoreLayer = (sql: SqlStorage): Layer.Layer<AuditStore> =>
  Layer.sync(AuditStore, () => makeAuditStore(sql));
