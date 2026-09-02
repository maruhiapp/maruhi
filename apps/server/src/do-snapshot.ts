// プロジェクト DO の退避(DO → R2)と復元 — docs/notes/hosted-ops.md §2-D / §2-E / §4-2。
//
// 退避物の形: NDJSON を gzip したオブジェクト。行の種類は
//   header  … 形式・スキーマ版・取得時刻・DO id(`idFromName` の像 — 一方向)
//   table   … 表名 + 列名(以後の row 行の values の順序)
//   row     … 表名 + 値配列(number / string / null。BLOB は { b64 } — 現行スキーマに
//             BLOB 列は無いが、値型の網羅として持つ)
//   trailer … 表ごとの行数・チェーンヘッド・監査 seq・監査ヘッド hex(列が最新のとき
//             のみ — 実体化の書き込みはしない)・databaseSize
// trailer が無い = 途中失敗の退避物であり、復元側は拒否する。
//
// 規律:
// - **プロジェクト ID をキー・ヘッダ・メタデータに載せない**(AUTH_SPEC §11-2 —
//   capability)。内容のチェーン genesis からは導出できる(それは DO の内容そのもの)
// - 読み出しは DO の permit 下(chain-do.ts)で、rowid キーセット + LIMIT を 1 文ずつ
//   同期に `toArray()` する。cursor を await 越しに持たない(storage-api docs: await 後の
//   cursor は後続の変更を観測しうる)。permit が変更を止めているので表間も一貫する
// - 追加の暗号化は行わない(CLAUDE.md — 仕様にない暗号操作を実装しない。内容は E2EE
//   暗号文 + 公開メタで DO に置いてある形と同一)
// - 復元は**空の DO(chain_entries が空)にのみ**書く。chain_entries は退避物の最後の表
//   なので、途中で失敗した復元はチェーンを持たず「未初期化」のままになり、再実行は
//   非チェーン表を消してやり直せる(上書き経路は存在しない)

import {
  OPS_RESTORE_BATCH_ROWS,
  OPS_SNAPSHOT_PART_BYTES,
  OPS_SNAPSHOT_ROW_PAGE,
} from "./ops-policy.ts";

export const SNAPSHOT_FORMAT = "maruhi-do-snapshot";
export const SNAPSHOT_FORMAT_VERSION = 1;

/** DO SQLite の束縛パラメータ上限(1 文あたり — durable-objects/platform/limits)。 */
const MAX_BOUND_PARAMETERS = 100;

type SnapshotScalar = number | string | null | { readonly b64: string };

export interface SnapshotHeader {
  readonly kind: "header";
  readonly format: typeof SNAPSHOT_FORMAT;
  readonly version: typeof SNAPSHOT_FORMAT_VERSION;
  readonly schemaVersion: number;
  readonly takenAtMs: number;
  readonly doIdHex: string;
}

interface SnapshotTableLine {
  readonly kind: "table";
  readonly table: string;
  readonly columns: readonly string[];
}

interface SnapshotRowLine {
  readonly kind: "row";
  readonly table: string;
  readonly values: readonly SnapshotScalar[];
}

export interface SnapshotTrailer {
  readonly kind: "trailer";
  readonly rows: Readonly<Record<string, number>>;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  readonly auditMaxSeq: number;
  /** 累積ハッシュ列(audit_head_hashes)が MAX(seq) に到達しているときのみ。 */
  readonly auditHeadHashHex: string | null;
  readonly databaseSizeBytes: number;
}

type SnapshotLine = SnapshotHeader | SnapshotTableLine | SnapshotRowLine | SnapshotTrailer;

// ---------------------------------------------------------------------------
// ウォーターマーク(skip 規則の入力 — hosted-ops §2-D)
// ---------------------------------------------------------------------------

export interface DoWatermarks {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  readonly auditMaxSeq: number;
  readonly auditHeadHashHex: string | null;
}

function maxSeq(sql: SqlStorage, table: string): number {
  const row = sql.exec(`SELECT COALESCE(MAX(seq), 0) AS m FROM ${table}`).one();
  return Number(row["m"]);
}

export function readWatermarks(sql: SqlStorage): DoWatermarks {
  const chainHeadSeq = maxSeq(sql, "chain_entries");
  const head = sql
    .exec("SELECT entry_hash_hex FROM chain_entries ORDER BY seq DESC LIMIT 1")
    .toArray()[0];
  const auditMaxSeq = maxSeq(sql, "audit_events");
  const headColumnSeq = maxSeq(sql, "audit_head_hashes");
  const auditHead =
    headColumnSeq === auditMaxSeq
      ? sql
          .exec("SELECT head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1")
          .toArray()[0]
      : undefined;
  return {
    chainHeadSeq,
    chainHeadHashHex: head === undefined ? null : String(head["entry_hash_hex"]),
    auditMaxSeq,
    auditHeadHashHex:
      auditMaxSeq === 0 ? "" : auditHead === undefined ? null : String(auditHead["head_hash_hex"]),
  };
}

/** chain_entries が空か(復元の受理条件 — 上書き経路を作らない)。 */
function isProjectDoEmpty(sql: SqlStorage): boolean {
  return sql.exec("SELECT 1 FROM chain_entries LIMIT 1").toArray().length === 0;
}

// ---------------------------------------------------------------------------
// 退避(書き出し)
// ---------------------------------------------------------------------------

/** 退避物の表の順序: chain_entries を**最後**に(復元の「チェーンが最後」規則の根拠)。 */
function snapshotTableOrder(tables: readonly string[]): readonly string[] {
  return [...tables.filter((t) => t !== "chain_entries"), "chain_entries"];
}

function encodeScalar(value: unknown): SnapshotScalar {
  if (value === null || typeof value === "number" || typeof value === "string") {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    let binary = "";
    for (const byte of new Uint8Array(value)) {
      binary += String.fromCharCode(byte);
    }
    return { b64: btoa(binary) };
  }
  throw new Error("unsupported SQLite value type in snapshot");
}

function decodeScalar(value: SnapshotScalar): number | string | null | ArrayBuffer {
  if (value !== null && typeof value === "object") {
    const binary = atob(value.b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
  return value;
}

/**
 * gzip 圧縮しながら R2 へ書く出力先。圧縮出力が 1 パート分溜まるごとに multipart の
 * パートとして送り、合計がパート長未満なら単一 put で終える。失敗時は multipart を
 * 中止する(未完了 upload はバケットのライフサイクル規則も掃除する)。
 */
class GzipObjectWriter {
  readonly #encoder = new TextEncoder();
  readonly #compressor = new CompressionStream("gzip");
  readonly #writer: WritableStreamDefaultWriter<BufferSource>;
  readonly #drain: Promise<void>;
  #pending: Uint8Array[] = [];
  #pendingBytes = 0;
  #upload: R2MultipartUpload | null = null;
  readonly #parts: R2UploadedPart[] = [];
  #totalBytes = 0;
  #drainError: unknown = null;

  constructor(
    private readonly bucket: R2Bucket,
    private readonly key: string,
    private readonly partBytes: number,
  ) {
    this.#writer = this.#compressor.writable.getWriter();
    this.#drain = this.#drainCompressed().catch((error: unknown) => {
      this.#drainError = error;
    });
  }

  async writeLine(line: string): Promise<void> {
    if (this.#drainError !== null) {
      throw this.#drainError;
    }
    await this.#writer.write(this.#encoder.encode(`${line}\n`));
  }

  async finish(): Promise<{ readonly bytes: number }> {
    await this.#writer.close();
    await this.#drain;
    if (this.#drainError !== null) {
      throw this.#drainError;
    }
    const last = this.#takePending();
    if (this.#upload === null) {
      await this.bucket.put(this.key, last);
    } else {
      this.#parts.push(await this.#upload.uploadPart(this.#parts.length + 1, last));
      await this.#upload.complete(this.#parts);
    }
    return { bytes: this.#totalBytes };
  }

  async abort(): Promise<void> {
    if (this.#upload !== null) {
      await this.#upload.abort();
    }
  }

  async #drainCompressed(): Promise<void> {
    const reader = this.#compressor.readable.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        return;
      }
      this.#pending.push(value);
      this.#pendingBytes += value.byteLength;
      this.#totalBytes += value.byteLength;
      // R2 の multipart は最終パート以外を**同一サイズ**に要求する(r2/api/workers/
      // workers-multipart-usage)ため、ちょうど partBytes ずつ切り出す
      while (this.#pendingBytes >= this.partBytes) {
        this.#upload ??= await this.bucket.createMultipartUpload(this.key);
        this.#parts.push(
          await this.#upload.uploadPart(this.#parts.length + 1, this.#takeExact(this.partBytes)),
        );
      }
    }
  }

  #takePending(): Uint8Array {
    return this.#takeExact(this.#pendingBytes);
  }

  /** 先頭から n バイトを切り出す(残りは pending に戻す)。 */
  #takeExact(n: number): Uint8Array {
    const merged = new Uint8Array(this.#pendingBytes);
    let offset = 0;
    for (const chunk of this.#pending) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const part = merged.slice(0, n);
    const rest = merged.slice(n);
    this.#pending = rest.byteLength === 0 ? [] : [rest];
    this.#pendingBytes = rest.byteLength;
    return part;
  }
}

export interface WriteSnapshotInput {
  readonly sql: SqlStorage;
  readonly tables: readonly string[];
  readonly schemaVersion: number;
  readonly doIdHex: string;
  readonly takenAtMs: number;
  readonly bucket: R2Bucket;
  readonly key: string;
  /** テスト用(既定は policy の 16 MiB)。 */
  readonly partBytes?: number;
}

export interface WriteSnapshotResult {
  readonly bytes: number;
  readonly trailer: SnapshotTrailer;
}

/** 退避物のキー(プロジェクト ID を含まない — DO id の像 + 取得時刻)。 */
export function snapshotObjectKey(prefix: string, doIdHex: string, takenAtMs: number): string {
  const stamp = new Date(takenAtMs).toISOString().replaceAll(":", "-");
  return `${prefix}/${doIdHex}/${stamp}.ndjson.gz`;
}

/**
 * 全表を読み出し R2 へ書く(呼び出し側が permit を保持していること)。表ごとに
 * rowid キーセットで 1 ページずつ同期に読む(cursor を await 越しに持たない)。
 */
export async function writeSnapshot(input: WriteSnapshotInput): Promise<WriteSnapshotResult> {
  const { sql } = input;
  const writer = new GzipObjectWriter(
    input.bucket,
    input.key,
    input.partBytes ?? OPS_SNAPSHOT_PART_BYTES,
  );
  try {
    const header: SnapshotHeader = {
      kind: "header",
      format: SNAPSHOT_FORMAT,
      version: SNAPSHOT_FORMAT_VERSION,
      schemaVersion: input.schemaVersion,
      takenAtMs: input.takenAtMs,
      doIdHex: input.doIdHex,
    };
    await writer.writeLine(JSON.stringify(header));
    const rows: Record<string, number> = {};
    for (const table of snapshotTableOrder(input.tables)) {
      const columns = sql.exec(`SELECT * FROM ${table} LIMIT 0`).columnNames;
      const tableLine: SnapshotTableLine = { kind: "table", table, columns };
      await writer.writeLine(JSON.stringify(tableLine));
      let count = 0;
      let lastRowid = -1;
      for (;;) {
        const page = Array.from(
          sql
            .exec(
              `SELECT rowid AS __rid, * FROM ${table} WHERE rowid > ? ORDER BY rowid LIMIT ?`,
              lastRowid,
              OPS_SNAPSHOT_ROW_PAGE,
            )
            .raw(),
        );
        for (const raw of page) {
          const [rowid, ...values] = raw;
          lastRowid = Number(rowid);
          const rowLine: SnapshotRowLine = {
            kind: "row",
            table,
            values: values.map(encodeScalar),
          };
          await writer.writeLine(JSON.stringify(rowLine));
          count += 1;
        }
        if (page.length < OPS_SNAPSHOT_ROW_PAGE) {
          break;
        }
      }
      rows[table] = count;
    }
    const marks = readWatermarks(sql);
    const trailer: SnapshotTrailer = {
      kind: "trailer",
      rows,
      chainHeadSeq: marks.chainHeadSeq,
      chainHeadHashHex: marks.chainHeadHashHex,
      auditMaxSeq: marks.auditMaxSeq,
      auditHeadHashHex: marks.auditHeadHashHex,
      databaseSizeBytes: sql.databaseSize,
    };
    await writer.writeLine(JSON.stringify(trailer));
    const { bytes } = await writer.finish();
    return { bytes, trailer };
  } catch (error) {
    await writer.abort();
    throw error;
  }
}

// ---------------------------------------------------------------------------
// 復元(読み込み)
// ---------------------------------------------------------------------------

/** 復元の拒否理由(静的コード — 結果ファイル・ログに載せてよい)。 */
export type RestoreFailureCode =
  | "not-empty"
  | "object-missing"
  | "malformed"
  | "schema-mismatch"
  | "trailer-missing"
  | "row-count-mismatch"
  | "unknown-table";

export class RestoreRefusedError extends Error {
  constructor(readonly code: RestoreFailureCode) {
    super(`restore refused: ${code}`);
  }
}

export interface RestoreSnapshotInput {
  /** transactionSync を持つ DO ストレージ(sql はここから取る)。 */
  readonly storage: DurableObjectStorage;
  readonly tables: readonly string[];
  readonly schemaVersion: number;
  readonly body: ReadableStream;
}

export interface RestoreSnapshotResult {
  readonly header: SnapshotHeader;
  readonly trailer: SnapshotTrailer;
  readonly rows: Readonly<Record<string, number>>;
}

async function* lines(body: ReadableStream): AsyncGenerator<string> {
  const reader = body
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new TextDecoderStream())
    .getReader();
  let carry = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      if (carry !== "") {
        yield carry;
      }
      return;
    }
    carry += value;
    let index = carry.indexOf("\n");
    while (index !== -1) {
      yield carry.slice(0, index);
      carry = carry.slice(index + 1);
      index = carry.indexOf("\n");
    }
  }
}

function parseLine(text: string): SnapshotLine {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // JSON でない行 = 退避物の破損(理由を静的コードへ畳む — 本文は運ばない)
    throw new RestoreRefusedError("malformed");
  }
  if (typeof parsed !== "object" || parsed === null || !("kind" in parsed)) {
    throw new RestoreRefusedError("malformed");
  }
  return parsed as SnapshotLine;
}

function wipeTables(sql: SqlStorage, tables: readonly string[]): void {
  for (const table of tables) {
    sql.exec(`DELETE FROM ${table}`);
  }
}

class RowInserter {
  #buffer: (readonly SnapshotScalar[])[] = [];
  readonly #rowsPerStatement: number;

  constructor(
    private readonly sql: SqlStorage,
    readonly table: string,
    private readonly columns: readonly string[],
  ) {
    this.#rowsPerStatement = Math.max(1, Math.floor(MAX_BOUND_PARAMETERS / columns.length));
  }

  push(values: readonly SnapshotScalar[]): void {
    if (values.length !== this.columns.length) {
      throw new RestoreRefusedError("malformed");
    }
    this.#buffer.push(values);
    if (this.#buffer.length >= OPS_RESTORE_BATCH_ROWS) {
      this.flush();
    }
  }

  flush(): void {
    if (this.#buffer.length === 0) {
      return;
    }
    const rows = this.#buffer;
    this.#buffer = [];
    const columnList = this.columns.join(", ");
    const placeholders = `(${this.columns.map(() => "?").join(", ")})`;
    for (let start = 0; start < rows.length; start += this.#rowsPerStatement) {
      const chunk = rows.slice(start, start + this.#rowsPerStatement);
      this.sql.exec(
        `INSERT INTO ${this.table} (${columnList}) VALUES ${chunk.map(() => placeholders).join(", ")}`,
        ...chunk.flatMap((values) => values.map(decodeScalar)),
      );
    }
  }
}

function acceptHeader(line: SnapshotLine, schemaVersion: number): SnapshotHeader {
  if (
    line.kind !== "header" ||
    line.format !== SNAPSHOT_FORMAT ||
    line.version !== SNAPSHOT_FORMAT_VERSION
  ) {
    throw new RestoreRefusedError("malformed");
  }
  if (line.schemaVersion !== schemaVersion) {
    throw new RestoreRefusedError("schema-mismatch");
  }
  return line;
}

/** 退避物の行を順に受け取り、表ごとにバッチ挿入する状態機械。 */
class RestoreReader {
  header: SnapshotHeader | null = null;
  trailer: SnapshotTrailer | null = null;
  readonly rows: Record<string, number> = {};
  #inserter: RowInserter | null = null;

  constructor(
    private readonly storage: DurableObjectStorage,
    private readonly known: ReadonlySet<string>,
    private readonly schemaVersion: number,
  ) {}

  accept(line: SnapshotLine): void {
    if (this.header === null) {
      this.header = acceptHeader(line, this.schemaVersion);
      return;
    }
    if (this.trailer !== null) {
      throw new RestoreRefusedError("malformed");
    }
    switch (line.kind) {
      case "table":
        this.#beginTable(line);
        return;
      case "row":
        this.#acceptRow(line);
        return;
      case "trailer":
        this.#flush();
        this.trailer = line;
        return;
      default:
        throw new RestoreRefusedError("malformed");
    }
  }

  /** 全表の行数がトレーラと一致することを検査して結果を返す。 */
  verify(tables: readonly string[]): RestoreSnapshotResult {
    const { header, trailer } = this;
    if (header === null || trailer === null) {
      throw new RestoreRefusedError("trailer-missing");
    }
    for (const table of tables) {
      if ((trailer.rows[table] ?? 0) !== (this.rows[table] ?? 0)) {
        throw new RestoreRefusedError("row-count-mismatch");
      }
    }
    return { header, trailer, rows: this.rows };
  }

  #beginTable(line: SnapshotTableLine): void {
    if (!this.known.has(line.table)) {
      throw new RestoreRefusedError("unknown-table");
    }
    this.#flush();
    this.#inserter = new RowInserter(this.storage.sql, line.table, line.columns);
    this.rows[line.table] = 0;
  }

  #acceptRow(line: SnapshotRowLine): void {
    const inserter = this.#inserter;
    if (inserter === null || line.table !== inserter.table) {
      throw new RestoreRefusedError("malformed");
    }
    inserter.push(line.values);
    this.rows[line.table] = (this.rows[line.table] ?? 0) + 1;
  }

  /** バッファ済みの行を 1 トランザクションで確定する。 */
  #flush(): void {
    const inserter = this.#inserter;
    if (inserter !== null) {
      this.storage.transactionSync(() => inserter.flush());
    }
  }
}

/**
 * 退避物を空の DO へ書き戻す(呼び出し側が permit を保持していること)。
 * バッチごとに transactionSync で原子コミットし、途中失敗(例外・トレーラ欠落・
 * 行数不一致)は全表を消して空へ戻してから投げる(チェーンが最後の表なので、
 * 消し損ねても「未初期化」側に倒れる)。
 */
export async function restoreSnapshot(input: RestoreSnapshotInput): Promise<RestoreSnapshotResult> {
  const { storage, tables } = input;
  if (!isProjectDoEmpty(storage.sql)) {
    throw new RestoreRefusedError("not-empty");
  }
  // 前回の部分復元(非チェーン表の残骸)を消してから始める
  wipeTables(storage.sql, tables);
  const reader = new RestoreReader(storage, new Set(tables), input.schemaVersion);
  try {
    for await (const text of lines(input.body)) {
      if (text !== "") {
        reader.accept(parseLine(text));
      }
    }
    return reader.verify(tables);
  } catch (error) {
    wipeTables(storage.sql, tables);
    throw error;
  }
}
