// `maruhi audit`(AUDIT_SPEC §6 / §7 — Phase 2 C1)。
//
// - list: project DO の監査イベント(新しい順、seq カーソル)。可視性クラス
//   (§6)はサーバーが強制し、ここは表示だけを担う
// - invites: invite.* の D1 読み取り(チェーン role admin — サーバー強制)
// - self: user 系イベントの本人閲覧(§3.1 / §6 — 要監視イベントの監視経路)
// - verify: チェーンミラーの全単射検証(§1-5「ミラーはチェーンから再構築
//   可能」/ §6 の緩和策「ミラーはチェーンと突合して検証できる」のクライアント
//   実装)。検証済みチェーンから期待ミラー列を再構築し、欠落・偽造・改変の
//   3 方向を検出する。写像はサーバーと共有(@maruhi/core の chainMirrorEvent)
//   — 二重管理による検証器ドリフトの誤警報を構造的に塞ぐ
//
// TCB 規律(AUDIT_SPEC §7): 応答の全フィールドはサーバー申告である。表示名は
// 検証済みメタステートメント(削除済み変数の tombstone 含む)からのみ解決し、
// payload の名前スナップショットは「記録」として区別表示する(表示名の位置に
// 昇格しない)。chain.* 行は検証済みチェーンとの突合結果をラベルで示す。
// 平文値・鍵素材はこのモジュールを通らない。

import { DEFAULT_AUDIT_EVENTS_PAGE_LIMIT, MAX_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
import type { AuditEventRecord } from "@maruhi/core";
import { chainMirrorEvent } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliServices, ProjectContextBase, SessionContext } from "./context.ts";
import { displayText } from "./display.ts";
import type { CliError } from "./errors.ts";
import { cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { type NameIndex, resolveNames } from "./rotation.ts";

/** ワイヤの監査イベント(api-schema の AuditEventSchema の受信形)。 */
interface WireAuditEvent {
  /** 行識別子 = row_id(不透明。--before カーソルに使う)。 */
  readonly id: string;
  /** 保存採番(admin 可視の project 応答のみ — AUDIT_SPEC §7)。 */
  readonly seq?: number;
  readonly serverTs: number;
  readonly clientTs?: number;
  readonly event: string;
  readonly actor: {
    readonly type: "user" | "server" | "system";
    readonly userId?: string;
    readonly keyFingerprintHex?: string;
    readonly apiTokenId?: string;
  };
  readonly targetUserId?: string;
  readonly targetKeyFingerprintHex?: string;
  readonly environmentId?: string;
  readonly variableId?: string;
  readonly epoch?: number;
  readonly version?: number;
  readonly chainSeq?: number;
  readonly projectId?: string;
  readonly payload?: Readonly<Record<string, unknown>>;
}

/** list / invites / self 共通のページ指定。before は前ページ末尾行の id。 */
export interface AuditPageOptions {
  readonly limit: number | null;
  readonly before: string | null;
}

/** list のフィルタ(AUDIT_SPEC §7 の語彙)。 */
export interface AuditListFilters {
  readonly event: string | null;
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly environmentId: string | null;
  readonly variableId: string | null;
}

// ---------------------------------------------------------------------------
// ミラー突合(§1-5 / §6)
// ---------------------------------------------------------------------------

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonRecordEqual(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((key) => key in right && jsonEqual(left[key], right[key]))
  );
}

/** JSON 値の構造的等価(キー順に依存しない)。 */
function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) {
    return true;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, index) => jsonEqual(item, b[index]));
  }
  return isJsonRecord(a) && isJsonRecord(b) && jsonRecordEqual(a, b);
}

function describeValue(value: unknown): string {
  return displayText(value === undefined ? "(なし)" : JSON.stringify(value));
}

/**
 * chain.* ミラー行と検証済みエントリの突合。サーバーと同一の写像
 * (chainMirrorEvent)から期待行を再構成し、不一致フィールドを列挙する
 * (空 = 一致)。serverTs はサーバー受理時刻(クライアントに検証材料がない)
 * のため対象外。chain.* の payload は署名済みエントリ由来なので突合対象。
 */
function mirrorMismatches(entry: ChainEntry, observed: WireAuditEvent): readonly string[] {
  const expected: AuditEventRecord = chainMirrorEvent(entry, observed.serverTs);
  const reasons: string[] = [];
  const check = (label: string, want: unknown, got: unknown): void => {
    if (!jsonEqual(want, got)) {
      reasons.push(`${label}: 期待 ${describeValue(want)} / 記録 ${describeValue(got)}`);
    }
  };
  check("event", expected.event, observed.event);
  check("client_ts", expected.clientTs, observed.clientTs);
  check("actor.type", expected.actorType, observed.actor.type);
  check("actor.user_id", expected.actorUserId, observed.actor.userId);
  check("actor.key_fingerprint", expected.actorKeyFingerprintHex, observed.actor.keyFingerprintHex);
  check("target.user_id", expected.targetUserId, observed.targetUserId);
  check(
    "target.key_fingerprint",
    expected.targetKeyFingerprintHex,
    observed.targetKeyFingerprintHex,
  );
  // 写像はミラー行に api_token_id を設定しない(§3.4 の actor はチェーン
  // エントリの写し)。期待は常に undefined だが、偽の「トークン経由」表示への
  // 誤導(pullfrog 指摘)を塞ぐため明示的に突合する
  check("actor.api_token_id", expected.actorApiTokenId, observed.actor.apiTokenId);
  check("environment_id", expected.environmentId, observed.environmentId);
  check("variable_id", expected.variableId, observed.variableId);
  check("epoch", expected.epoch, observed.epoch);
  check("version", expected.version, observed.version);
  check("payload", expected.payload, observed.payload);
  return reasons;
}

/** 検証済みチェーンの seq → エントリ索引。 */
function entryIndexOf(entries: readonly ChainEntry[]): ReadonlyMap<number, ChainEntry> {
  return new Map(entries.map((entry) => [entry.seq, entry]));
}

/** chain.* 行のトラストラベル(表示用)と不一致詳細。 */
interface MirrorTrust {
  readonly label: string;
  readonly mismatches: readonly string[];
}

function mirrorTrustOf(
  observed: WireAuditEvent,
  entries: ReadonlyMap<number, ChainEntry>,
  headSeq: number,
): MirrorTrust {
  if (observed.chainSeq === undefined) {
    return { label: "突合=不一致", mismatches: ["chain_seq: ミラー行が chain_seq を持ちません"] };
  }
  if (observed.chainSeq > headSeq) {
    // 同期後にチェーンが伸びた正直なレースでも起きる — 単独では証拠にしないが、
    // 偽造との区別(head 直後からの連続性)は verify が確定する
    return {
      label: "突合=未検証(ローカルのチェーンより新しい — maruhi audit verify で確定してください)",
      mismatches: [],
    };
  }
  const entry = entries.get(observed.chainSeq);
  if (entry === undefined) {
    return {
      label: "突合=不一致",
      mismatches: [`chain_seq: 検証済みチェーンに seq=${observed.chainSeq} のエントリがありません`],
    };
  }
  const mismatches = mirrorMismatches(entry, observed);
  return mismatches.length === 0
    ? { label: "突合=OK", mismatches }
    : { label: "突合=不一致", mismatches };
}

// ---------------------------------------------------------------------------
// 表示
// ---------------------------------------------------------------------------

function formatTs(ms: number): string {
  return new Date(ms).toISOString().slice(0, 19).replace("T", " ") + " UTC";
}

function describeActor(event: WireAuditEvent): string {
  const actor = event.actor;
  if (actor.type === "server") {
    return `server:fp=${actor.keyFingerprintHex ?? "?"}`;
  }
  if (actor.type === "system") {
    return "system";
  }
  const id = actor.userId === undefined ? "(不明)" : displayText(actor.userId);
  const viaToken = actor.apiTokenId === undefined ? "" : "(トークン経由)";
  return `user:${id}${viaToken}`;
}

function describeTarget(event: WireAuditEvent): string | null {
  if (event.targetUserId !== undefined) {
    return `target=${displayText(event.targetUserId)}`;
  }
  if (event.targetKeyFingerprintHex !== undefined) {
    return `target=server:${event.targetKeyFingerprintHex}`;
  }
  return null;
}

/** 座標・数値部の列(env / var / epoch / version — 無いものは出さない)。 */
function coordinateParts(event: WireAuditEvent, resolvedName: string | null): readonly string[] {
  const parts: string[] = [];
  if (event.environmentId !== undefined) {
    parts.push(`env=${displayText(event.environmentId)}`);
  }
  if (event.variableId !== undefined) {
    const label =
      resolvedName === null
        ? displayText(event.variableId)
        : `${displayText(resolvedName)}(${displayText(event.variableId)})`;
    parts.push(`var=${label}`);
  }
  if (event.epoch !== undefined) {
    parts.push(`epoch=${event.epoch}`);
  }
  if (event.version !== undefined) {
    parts.push(`version=${event.version}`);
  }
  return parts;
}

/** 末尾部の列(chain_seq + 突合ラベル / 記録 payload)。 */
function trailerParts(event: WireAuditEvent, trust: MirrorTrust | null): readonly string[] {
  const parts: string[] = [];
  if (event.chainSeq !== undefined || trust !== null) {
    const seqPart = event.chainSeq === undefined ? "" : `chain_seq=${event.chainSeq}`;
    parts.push(trust === null ? seqPart : `${seqPart}(${trust.label})`);
  }
  if (event.payload !== undefined) {
    // 記録内容(サーバー申告)であることを明示する接頭辞。名前スナップショット
    // を含みうるが、表示名の位置(var= ラベル)には昇格しない(TCB 規律)
    parts.push(`記録=${displayText(JSON.stringify(event.payload))}`);
  }
  return parts;
}

/** 1 行の描画。表示名(resolvedName)は検証済みステートメント由来のみ。 */
function formatEventLine(
  event: WireAuditEvent,
  resolvedName: string | null,
  trust: MirrorTrust | null,
): string {
  const target = describeTarget(event);
  return [
    // seq は admin 可視の応答にのみ載る(§7 — 非 admin には序数を出さない)
    ...(event.seq === undefined ? [] : [`seq=${event.seq}`]),
    formatTs(event.serverTs),
    displayText(event.event),
    `actor=${describeActor(event)}`,
    ...(target === null ? [] : [target]),
    ...coordinateParts(event, resolvedName),
    ...trailerParts(event, trust),
  ].join("\t");
}

/** ページ末尾の続きの案内(limit いっぱい返ったときだけ)。 */
function continuationHint(
  events: readonly WireAuditEvent[],
  requestedLimit: number | null,
  command: string,
): string | null {
  const pageSize = requestedLimit ?? DEFAULT_AUDIT_EVENTS_PAGE_LIMIT;
  const last = events[events.length - 1];
  if (last === undefined || events.length < pageSize) {
    return null;
  }
  return `続きを見るには: ${command} --before ${last.id}`;
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

function fetchProjectEvents(
  client: MaruhiClient,
  projectId: string,
  page: AuditPageOptions,
  filters: AuditListFilters,
): Effect.Effect<readonly WireAuditEvent[], CliError> {
  return client.audit
    .events({
      params: { projectId },
      query: {
        ...pageQueryOf(page),
        ...(filters.event === null ? {} : { event: filters.event }),
        ...(filters.actorUserId === null ? {} : { actorUserId: filters.actorUserId }),
        ...(filters.targetUserId === null ? {} : { targetUserId: filters.targetUserId }),
        ...(filters.variableId === null ? {} : { variableId: filters.variableId }),
        ...(filters.environmentId === null ? {} : { environmentId: filters.environmentId }),
      },
    })
    .pipe(
      Effect.mapError(toCliError),
      Effect.map((response) => response.events),
    );
}

/**
 * `maruhi audit`(list): 監査イベントの表示。chain.* 行は検証済みチェーンと
 * 突合し、不一致(= 改竄の証拠)があれば終了コード 1(invite list の
 * 完全性検査と同じ規律 — 読めたことと健全であることを混ぜない)。
 */
/** 名前解決の対象になる環境 ID の集合(variableId を持つ行の環境のみ)。 */
function environmentIdsForNames(events: readonly WireAuditEvent[]): readonly string[] {
  const ids = new Set<string>();
  for (const event of events) {
    if (event.variableId !== undefined && event.environmentId !== undefined) {
      ids.add(event.environmentId);
    }
  }
  return [...ids].toSorted();
}

/** 1 行分の描画結果(本文 + ミラー不一致の警告列)。純関数 — Effect を持たない。 */
function renderListEvent(
  event: WireAuditEvent,
  names: ReadonlyMap<string, NameIndex>,
  entries: ReadonlyMap<number, ChainEntry>,
  headSeq: number,
): { readonly line: string; readonly warnings: readonly string[] } {
  const name =
    event.environmentId === undefined || event.variableId === undefined
      ? null
      : (names.get(event.environmentId)?.get(event.variableId) ?? null);
  const trust = event.event.startsWith("chain.") ? mirrorTrustOf(event, entries, headSeq) : null;
  const warnings = (trust?.mismatches ?? []).map(
    (mismatch) =>
      `警告: 監査行 ${event.id} のミラー行が検証済みチェーンと一致しません — ${mismatch}(監査ログはサーバー管理データであり、この不一致はサーバーによる改竄・破損の証拠です — AUDIT_SPEC §6)`,
  );
  return { line: formatEventLine(event, name, trust), warnings };
}

export function auditListOp(
  context: ProjectContextBase,
  page: AuditPageOptions,
  filters: AuditListFilters,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const events = yield* fetchProjectEvents(context.client, context.projectId, page, filters);
    if (events.length === 0) {
      yield* io.log("監査イベントはありません(フィルタ・カーソルに一致する行なし)");
      return 0;
    }
    const names = yield* resolveNames(context, environmentIdsForNames(events));
    const entries = entryIndexOf(context.verified.entries);
    let integrityFailures = 0;
    for (const event of events) {
      const rendered = renderListEvent(event, names, entries, context.verified.state.headSeq);
      yield* io.log(rendered.line);
      integrityFailures += rendered.warnings.length;
      for (const warning of rendered.warnings) {
        yield* io.logError(warning);
      }
    }
    const hint = continuationHint(events, page.limit, "maruhi audit");
    if (hint !== null) {
      yield* io.log(hint);
    }
    return integrityFailures > 0 ? 1 : 0;
  });
}

// ---------------------------------------------------------------------------
// invites / self
// ---------------------------------------------------------------------------

/** ページ指定 → クエリ(未指定キーは送らない = サーバー既定に任せる)。 */
function pageQueryOf(page: AuditPageOptions): { before?: string; limit?: number } {
  return {
    ...(page.before === null ? {} : { before: page.before }),
    ...(page.limit === null ? {} : { limit: page.limit }),
  };
}

/** D1 側ページ(invites / self)の共通経路: 取得 → 一覧描画 → 続きの案内。 */
function fetchAndRenderD1Events(input: {
  readonly request: Effect.Effect<{ readonly events: readonly WireAuditEvent[] }, unknown>;
  readonly page: AuditPageOptions;
  readonly emptyMessage: string;
  readonly command: string;
}): Effect.Effect<readonly WireAuditEvent[], CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const events = yield* input.request.pipe(
      Effect.mapError(toCliError),
      Effect.map((response) => response.events),
    );
    if (events.length === 0) {
      yield* io.log(input.emptyMessage);
      return events;
    }
    for (const event of events) {
      yield* io.log(formatEventLine(event, null, null));
    }
    const hint = continuationHint(events, input.page.limit, input.command);
    if (hint !== null) {
      yield* io.log(hint);
    }
    return events;
  });
}

/** `maruhi audit invites`: invite.* の監査行(チェーン role admin — サーバー強制)。 */
export function auditInvitesOp(
  context: ProjectContextBase,
  page: AuditPageOptions,
): Effect.Effect<number, CliError, CliServices> {
  return fetchAndRenderD1Events({
    request: context.client.audit.invites({
      params: { projectId: context.projectId },
      query: pageQueryOf(page),
    }),
    page,
    emptyMessage: "招待の監査イベントはありません",
    command: "maruhi audit invites",
  }).pipe(Effect.as(0));
}

/** `maruhi audit self`: 自分のアカウント系イベント(§3.1 — 要監視イベントの監視)。 */
export function auditSelfOp(
  context: SessionContext,
  page: AuditPageOptions,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const events = yield* fetchAndRenderD1Events({
      request: context.client.audit.self({ query: pageQueryOf(page) }),
      page,
      emptyMessage: "アカウントの監査イベントはありません",
      command: "maruhi audit self",
    });
    // 要監視イベント(AUDIT_SPEC §3.1)の含意はここで一度だけ添える
    if (events.some((event) => event.event === "auth.recovery_blob_fetched")) {
      yield* io.log(
        "注意: auth.recovery_blob_fetched(ラップ済み master 秘密鍵の取得)が含まれています。心当たりのない取得がある場合はリカバリーコードを再発行し(maruhi key recovery)、トークン・セッションを失効させてください",
      );
    }
    return 0;
  });
}

// ---------------------------------------------------------------------------
// verify(ミラー全単射検証)
// ---------------------------------------------------------------------------

/** §3.4 のミラーイベント名(chainMirrorEvent の像と一対一)。 */
const MIRROR_EVENTS: readonly string[] = [
  "chain.genesis",
  "chain.member_added",
  "chain.member_removed",
  "chain.role_changed",
  "chain.environment_created",
  "chain.epoch_rotated",
  "chain.server_granted",
  "chain.server_revoked",
];

const VERIFY_PAGE_LIMIT = MAX_AUDIT_EVENTS_PAGE_LIMIT;
// チェーン受理ポリシー(10,000 エントリ)÷ ページ 200 = 50 ページが理論最大。
// カーソルが前進しないサーバーで無限ループしないための硬い上限
const VERIFY_MAX_PAGES_PER_EVENT = 100;

/**
 * 1 イベント種別の全ページ取得(新しい順。カーソルは行 id)。同じ行 id が
 * 再登場したらサーバー応答の矛盾(カーソル非前進・行の重複配布)として拒否する
 * — id は不透明で序数比較ができないため、前進性は集合の非重複で検査する。
 */
function fetchAllMirrorRows(
  client: MaruhiClient,
  projectId: string,
  event: string,
): Effect.Effect<readonly WireAuditEvent[], CliError> {
  return Effect.gen(function* () {
    const rows: WireAuditEvent[] = [];
    const seen = new Set<string>();
    let before: string | null = null;
    for (let pageCount = 0; pageCount < VERIFY_MAX_PAGES_PER_EVENT; pageCount += 1) {
      const cursor = before;
      const page: readonly WireAuditEvent[] = yield* client.audit
        .events({
          params: { projectId },
          query: {
            event,
            limit: VERIFY_PAGE_LIMIT,
            ...(cursor === null ? {} : { before: cursor }),
          },
        })
        .pipe(
          Effect.mapError(toCliError),
          Effect.map((response) => response.events as readonly WireAuditEvent[]),
        );
      for (const row of page) {
        if (seen.has(row.id)) {
          return yield* Effect.fail(
            cliError(
              `監査ログのページングが前進しません(event=${displayText(event)}, 行 ${displayText(row.id)} が重複して返りました)— サーバー応答の矛盾です。ミラー検証を中断します`,
            ),
          );
        }
        seen.add(row.id);
        rows.push(row);
      }
      if (page.length < VERIFY_PAGE_LIMIT) {
        return rows;
      }
      before = page[page.length - 1]?.id ?? null;
    }
    return yield* Effect.fail(
      cliError("監査ログのページ数が理論上限を超えました — サーバー応答の矛盾です"),
    );
  });
}

/** ミラー行の索引化の結果(chain_seq で束ね、検証不能な行を分別)。 */
interface MirrorBuckets {
  readonly byChainSeq: ReadonlyMap<number, readonly WireAuditEvent[]>;
  readonly problems: readonly string[];
  /** head 直後から連続する「ローカルのチェーンより新しい」行数(未検証)。 */
  readonly aheadRows: number;
}

/**
 * head より新しい行の連続性検査。正直な伸長(同期とページ取得の間にチェーンが
 * 進んだ)なら、その行の chain_seq は head+1 から欠番・重複なく連続する — ミラーは
 * 受理と同一トランザクションで書かれ、seq は無欠番だからである(§3.4 / §5.1)。
 * 連続しない・重複する行は「実在しないエントリを名乗る偽造行」の証拠として
 * 扱う(pullfrog 指摘 — 到達し得ない chain_seq による検証回避を塞ぐ)。
 */
function aheadContiguityProblems(ahead: readonly number[], headSeq: number): readonly string[] {
  const problems: string[] = [];
  let expected = headSeq + 1;
  for (const chainSeq of [...ahead].toSorted((a, b) => a - b)) {
    if (chainSeq !== expected) {
      problems.push(
        `chain_seq=${chainSeq}: ローカルのチェーン(head seq=${headSeq})より新しいミラー行が head 直後から連続していません(期待 ${expected})— 正直な伸長なら欠番・重複なく連続するため、実在しないエントリを名乗る偽造行の証拠です`,
      );
    }
    expected = chainSeq + 1;
  }
  return problems;
}

/** 取得した chain.* 行を chain_seq で索引化する(検証の前段の純関数)。 */
function bucketMirrorRows(rows: readonly WireAuditEvent[], headSeq: number): MirrorBuckets {
  const byChainSeq = new Map<number, WireAuditEvent[]>();
  const problems: string[] = [];
  const ahead: number[] = [];
  for (const row of rows) {
    if (row.chainSeq === undefined) {
      problems.push(
        `監査行 ${displayText(row.id)}: ミラー行が chain_seq を持ちません(${displayText(row.event)})`,
      );
    } else if (row.chainSeq > headSeq) {
      ahead.push(row.chainSeq);
    } else {
      byChainSeq.set(row.chainSeq, [...(byChainSeq.get(row.chainSeq) ?? []), row]);
    }
  }
  problems.push(...aheadContiguityProblems(ahead, headSeq));
  return { byChainSeq, problems, aheadRows: ahead.length };
}

/** 1 エントリ分の全単射 + 写像一致の検査(空 = 問題なし)。 */
function entryMirrorProblems(
  entry: ChainEntry,
  matched: readonly WireAuditEvent[],
): readonly string[] {
  const observed = matched[0];
  if (observed === undefined) {
    return [
      `chain_seq=${entry.seq}(op=${entry.op}): 対応するミラー行がありません(欠落 — ミラーはチェーン受理と同一トランザクションで書かれるため、削除の隠蔽の証拠です)`,
    ];
  }
  if (matched.length > 1) {
    return [
      `chain_seq=${entry.seq}(op=${entry.op}): ミラー行が ${matched.length} 行あります(重複 — 行 ${matched.map((row) => displayText(row.id)).join(", ")})`,
    ];
  }
  return mirrorMismatches(entry, observed).map(
    (mismatch) => `chain_seq=${entry.seq}(監査行 ${displayText(observed.id)}): ${mismatch}`,
  );
}

/**
 * `maruhi audit verify`: ミラー全単射検証。検証済みチェーンの全エントリ
 * (1..headSeq)と chain.* ミラー行が 1 対 1 に対応し、全フィールドが写像どおり
 * であることを検査する。欠落(削除の隠蔽)・偽造(チェーンにない行)・改変の
 * 3 方向を検出する — per-row 突合(list のラベル)では原理的に見えない欠落まで
 * 覆うのがこのコマンドの追加価値。クラス 1 のみを読むため全メンバーが実行できる。
 */
export function auditVerifyOp(
  context: ProjectContextBase,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const rows: WireAuditEvent[] = [];
    for (const event of MIRROR_EVENTS) {
      rows.push(...(yield* fetchAllMirrorRows(context.client, context.projectId, event)));
    }
    const headSeq = context.verified.state.headSeq;
    const buckets = bucketMirrorRows(rows, headSeq);
    const problems = [
      ...buckets.problems,
      ...context.verified.entries.flatMap((entry) =>
        entryMirrorProblems(entry, buckets.byChainSeq.get(entry.seq) ?? []),
      ),
    ];
    if (problems.length === 0 && buckets.aheadRows === 0) {
      yield* io.log(
        `ミラー全単射検証 OK: チェーン ${headSeq} エントリ ↔ chain.* ミラー行が写像(AUDIT_SPEC §3.4)どおり一致しました`,
      );
      return 0;
    }
    if (buckets.aheadRows > 0) {
      // 未検証の行が残る限り「OK」とは言わない(pullfrog 指摘 — 偽造行が
      // 未検証枠に恒久に居座る形を、成功終了で覆い隠さない)
      yield* io.logError(
        `ミラー検証未完: ${buckets.aheadRows} 行はローカルのチェーンより新しく、今回の実行では検証できませんでした(同期直後にチェーンが伸びた場合に起きえます)。maruhi audit verify を再実行してください — 再実行しても解消しない場合、そのミラー行はチェーンに実在しないエントリを名乗っています(偽造の疑い)`,
      );
    }
    for (const problem of problems) {
      yield* io.logError(`ミラー検証失敗: ${problem}`);
    }
    if (problems.length > 0) {
      yield* io.logError(
        `ミラー検証で ${problems.length} 件の不一致を検出しました。監査ログはサーバー管理データであり(AUDIT_SPEC §6)、この不一致はサーバーによる改竄・破損の証拠です — 配布チェーン(署名付き・検証済み)側が真であり、監査ログを信用しないでください`,
      );
    }
    return 1;
  });
}
