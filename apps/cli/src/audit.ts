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
import { CHAIN_MIRROR_EVENT_PREFIX, CHAIN_MIRROR_EVENTS, chainMirrorEvent } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliServices, ProjectContextBase, SessionContext } from "./context.ts";
import { countNoun, displayText, formatUtcSeconds } from "./display.ts";
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
  return displayText(value === undefined ? "(none)" : JSON.stringify(value));
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
      reasons.push(`${label}: expected ${describeValue(want)} / recorded ${describeValue(got)}`);
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
    return { label: "mirror=mismatch", mismatches: ["chain_seq: the mirror row has no chain_seq"] };
  }
  if (observed.chainSeq > headSeq) {
    // 同期後にチェーンが伸びた正直なレースでも起きる — 単独では証拠にしないが、
    // 偽造との区別(head 直後からの連続性)は verify が確定する
    return {
      label: "mirror=unverified (newer than the local chain — confirm with maruhi audit verify)",
      mismatches: [],
    };
  }
  const entry = entries.get(observed.chainSeq);
  if (entry === undefined) {
    return {
      label: "mirror=mismatch",
      mismatches: [`chain_seq: the verified chain has no entry at seq=${observed.chainSeq}`],
    };
  }
  const mismatches = mirrorMismatches(entry, observed);
  return mismatches.length === 0
    ? { label: "mirror=OK", mismatches }
    : { label: "mirror=mismatch", mismatches };
}

/**
 * event 名が chain.* 外なのに chain_seq を持つ行の明示的な不信ラベル(S1)。
 *
 * 正直なサーバーで chainSeq を設定する唯一の書き手は chainMirrorEvent なので、
 * この組み合わせは provenance claim の偽造を示す。イベント名だけを起点にすると
 * 名前空間の 1 歩外へ逃げた行が素の `chain_seq=N` として表示され、verify の
 * eventPrefix=chain. にも入らない。
 */
function outsideChainNamespaceTrust(event: WireAuditEvent): MirrorTrust | null {
  if (event.chainSeq === undefined || event.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
    return null;
  }
  return {
    label: "mirror=unverified (chain_seq is invalid outside the chain.* namespace)",
    mismatches: [
      `event: chain_seq is present on ${displayText(event.event)}, but only chain.* mirror rows may carry chain provenance`,
    ],
  };
}

/** project 監査行の provenance 判定。chainSeq の存在をイベント名より先に見る。 */
function projectMirrorTrustOf(
  event: WireAuditEvent,
  entries: ReadonlyMap<number, ChainEntry>,
  headSeq: number,
): MirrorTrust | null {
  return (
    outsideChainNamespaceTrust(event) ??
    (event.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)
      ? mirrorTrustOf(event, entries, headSeq)
      : null)
  );
}

/** D1 経路(invites / self)は chain provenance を保存しない。あれば偽造・破損。 */
function d1MirrorTrustOf(event: WireAuditEvent): MirrorTrust | null {
  if (event.chainSeq === undefined) {
    return null;
  }
  return {
    label: "mirror=unverified (chain_seq is invalid on this audit endpoint)",
    mismatches: [
      `chain_seq: ${event.chainSeq} is present on a D1-backed audit row, but this endpoint does not store chain provenance`,
    ],
  };
}

/** trust の不一致を端末警告へ写す(空 = 未検証だが単独では改竄断定しない)。 */
function mirrorWarnings(event: WireAuditEvent, trust: MirrorTrust | null): readonly string[] {
  return (trust?.mismatches ?? []).map(
    (mismatch) =>
      `Warning: audit row ${event.id} makes a chain provenance claim that is invalid or does not match the verified chain — ${mismatch} (the audit log is server-managed data, so this mismatch is evidence of server-side tampering or corruption — AUDIT_SPEC §6)`,
  );
}

// ---------------------------------------------------------------------------
// 表示
// ---------------------------------------------------------------------------

// serverTs はサーバー申告の無制限 number(B1): total な共有フォーマッタで表示し、
// Date 範囲外の値が defect(RangeError)にならないようにする
const formatTs = formatUtcSeconds;

function describeActor(event: WireAuditEvent): string {
  const actor = event.actor;
  if (actor.type === "server") {
    return `server:fp=${actor.keyFingerprintHex ?? "?"}`;
  }
  if (actor.type === "system") {
    return "system";
  }
  const id = actor.userId === undefined ? "(unknown)" : displayText(actor.userId);
  const viaToken = actor.apiTokenId === undefined ? "" : " (via token)";
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
        : `${displayText(resolvedName)} (${displayText(event.variableId)})`;
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
    if (trust === null) {
      // 呼び出し側が trust 計算を忘れても、chain_seq を検証済み座標のように
      // 無ラベル表示しない(S1 の最後の防衛線)
      parts.push(`${seqPart} (mirror=unverified — no chain verification context)`);
    } else {
      parts.push(seqPart === "" ? `(${trust.label})` : `${seqPart} (${trust.label})`);
    }
  }
  if (event.payload !== undefined) {
    // 記録内容(サーバー申告)であることを明示する接頭辞。名前スナップショット
    // を含みうるが、表示名の位置(var= ラベル)には昇格しない(TCB 規律)
    parts.push(`recorded=${displayText(JSON.stringify(event.payload))}`);
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
  return `To continue: ${command} --before ${last.id}`;
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
  const trust = projectMirrorTrustOf(event, entries, headSeq);
  const warnings = mirrorWarnings(event, trust);
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
      yield* io.log("No audit events (no rows match the filter / cursor)");
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

interface D1AuditRenderResult {
  readonly events: readonly WireAuditEvent[];
  readonly integrityFailures: number;
}

/** D1 側ページ(invites / self)の共通経路: 取得 → 一覧描画 → 続きの案内。 */
function fetchAndRenderD1Events(input: {
  readonly request: Effect.Effect<{ readonly events: readonly WireAuditEvent[] }, unknown>;
  readonly page: AuditPageOptions;
  readonly emptyMessage: string;
  readonly command: string;
}): Effect.Effect<D1AuditRenderResult, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const events = yield* input.request.pipe(
      Effect.mapError(toCliError),
      Effect.map((response) => response.events),
    );
    if (events.length === 0) {
      yield* io.log(input.emptyMessage);
      return { events, integrityFailures: 0 };
    }
    let integrityFailures = 0;
    for (const event of events) {
      // D1 行は chain provenance を持たない。悪意ある応答が chain_seq を差しても
      // 素の座標として表示せず、警告 + 非ゼロ終了にする(S1)
      const trust = d1MirrorTrustOf(event);
      const warnings = mirrorWarnings(event, trust);
      yield* io.log(formatEventLine(event, null, trust));
      integrityFailures += warnings.length;
      for (const warning of warnings) {
        yield* io.logError(warning);
      }
    }
    const hint = continuationHint(events, input.page.limit, input.command);
    if (hint !== null) {
      yield* io.log(hint);
    }
    return { events, integrityFailures };
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
    emptyMessage: "No invite audit events",
    command: "maruhi audit invites",
  }).pipe(Effect.map((result) => (result.integrityFailures > 0 ? 1 : 0)));
}

/** `maruhi audit self`: 自分のアカウント系イベント(§3.1 — 要監視イベントの監視)。 */
export function auditSelfOp(
  context: SessionContext,
  page: AuditPageOptions,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const rendered = yield* fetchAndRenderD1Events({
      request: context.client.audit.self({ query: pageQueryOf(page) }),
      page,
      emptyMessage: "No account audit events",
      command: "maruhi audit self",
    });
    const events = rendered.events;
    // 要監視イベント(AUDIT_SPEC §3.1)の含意はここで一度だけ添える
    if (events.some((event) => event.event === "auth.recovery_blob_fetched")) {
      yield* io.log(
        "Note: auth.recovery_blob_fetched (a fetch of the wrapped master private key) is present. If you do not recognize a fetch, reissue your recovery code (maruhi key recovery) and revoke your tokens and sessions",
      );
    }
    return rendered.integrityFailures > 0 ? 1 : 0;
  });
}

// ---------------------------------------------------------------------------
// verify(ミラー全単射検証)
// ---------------------------------------------------------------------------

// §3.4 のミラーイベント名は共有写像(@maruhi/core の CHAIN_MIRROR_EVENTS —
// ChainOp の全域マップから導出)を使う。手書きリストだと将来の op 追加時に
// ここだけ漏れ、連続性検査が正直なサーバーを偽造と誤断定する(pullfrog 指摘)

const VERIFY_PAGE_LIMIT = MAX_AUDIT_EVENTS_PAGE_LIMIT;
// チェーン受理ポリシー(10,000 エントリ)÷ ページ 200 = 50 ページが理論最大。
// カーソルが前進しないサーバーで無限ループしないための硬い上限。名前空間ごと
// 1 回のページングで全ミラー行を引くため、上限もイベント種別ごとではなく通し
const VERIFY_MAX_PAGES = 100;

type MirrorRowSelector = "chain-namespace" | "chain-seq-present";

/**
 * 1 つのミラー候補フィルタを全ページ取得(新しい順。カーソルは行 id)。
 * 同じ行 id が再登場したらサーバー応答の矛盾(カーソル非前進・行の重複配布)
 * として拒否する — id は不透明で序数比較ができないため、前進性は集合の
 * 非重複で検査する。
 */
function fetchMirrorRowsForSelector(
  client: MaruhiClient,
  projectId: string,
  selector: MirrorRowSelector,
): Effect.Effect<readonly WireAuditEvent[], CliError> {
  return Effect.gen(function* () {
    const rows: WireAuditEvent[] = [];
    const seen = new Set<string>();
    let before: string | null = null;
    for (let pageCount = 0; pageCount < VERIFY_MAX_PAGES; pageCount += 1) {
      const cursor = before;
      const page: readonly WireAuditEvent[] = yield* client.audit
        .events({
          params: { projectId },
          query: {
            limit: VERIFY_PAGE_LIMIT,
            ...(selector === "chain-namespace"
              ? { eventPrefix: CHAIN_MIRROR_EVENT_PREFIX }
              : { chainSeqPresent: "true" as const }),
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
              `Audit-log paging is not advancing (${selector}, row ${displayText(row.id)} was returned twice) — the server response contradicts itself. Aborting the mirror verification`,
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
      cliError(
        "The audit log exceeded the theoretical page-count limit — the server response contradicts itself",
      ),
    );
  });
}

/**
 * verify のミラー候補全体。2 つの集合を和集合にする:
 *
 * 1. `chain.` 名前空間の全行 — 写像に無い名前・chain_seq 欠落も拾う(R1)
 * 2. chain_seq を持つ全行 — 名前空間の 1 歩外にある偽 provenance を拾う(S1)
 *
 * 正当なミラー行は両方に入るので row id で重複排除する。同じ id なのに内容が
 * フィルタ間で変わったら、サーバー応答が自己矛盾しており検証を続けられない。
 */
function fetchAllMirrorRows(
  client: MaruhiClient,
  projectId: string,
): Effect.Effect<readonly WireAuditEvent[], CliError> {
  return Effect.gen(function* () {
    const byId = new Map<string, WireAuditEvent>();
    for (const selector of ["chain-namespace", "chain-seq-present"] as const) {
      const rows = yield* fetchMirrorRowsForSelector(client, projectId, selector);
      for (const row of rows) {
        const existing = byId.get(row.id);
        if (existing !== undefined && !jsonEqual(existing, row)) {
          return yield* Effect.fail(
            cliError(
              `Audit row ${displayText(row.id)} changed between mirror-verification queries — the server response contradicts itself`,
            ),
          );
        }
        byId.set(row.id, row);
      }
    }
    return [...byId.values()];
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
        `chain_seq=${chainSeq}: mirror rows newer than the local chain (head seq=${headSeq}) are not contiguous from just after the head (expected ${expected}) — an honest extension is contiguous with no gaps or duplicates, so this is evidence of forged rows claiming nonexistent entries`,
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
    // chain_seq の存在をイベント名より先に信頼境界として扱う(S1)。正当な
    // chain_seq の唯一の書き手は chainMirrorEvent なので、名前空間外の行は
    // 実在する op と突合する余地のない偽 provenance claim である
    if (!row.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
      problems.push(
        `Audit row ${displayText(row.id)}: chain_seq=${row.chainSeq ?? "(missing)"} is present outside the chain.* namespace (${displayText(row.event)}) — only chain mirror rows may carry chain provenance (evidence of a forged row)`,
      );
      continue;
    }
    // 名前空間内で写像に無いイベント名は、それ自体が偽造の証拠(deepsec R1):
    // 実在する op のミラーは必ず chainMirrorEvent の像に入る。chain_seq の
    // 突合に進める行ではないので、ここで問題として確定させて次の行へ進む
    if (!CHAIN_MIRROR_EVENTS.includes(row.event)) {
      problems.push(
        `Audit row ${displayText(row.id)}: the mirror row claims an unknown chain op (${displayText(row.event)}) — no chain operation maps to this event name, so the row cannot mirror a real entry (evidence of a forged row)`,
      );
      continue;
    }
    if (row.chainSeq === undefined) {
      problems.push(
        `Audit row ${displayText(row.id)}: the mirror row has no chain_seq (${displayText(row.event)})`,
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
      `chain_seq=${entry.seq} (op=${entry.op}): no corresponding mirror row (a missing row — mirrors are written in the same transaction as chain acceptance, so this is evidence of a concealed deletion)`,
    ];
  }
  if (matched.length > 1) {
    return [
      `chain_seq=${entry.seq} (op=${entry.op}): ${countNoun(matched.length, "mirror row")} found (duplicates — rows ${matched.map((row) => displayText(row.id)).join(", ")})`,
    ];
  }
  return mirrorMismatches(entry, observed).map(
    (mismatch) => `chain_seq=${entry.seq} (audit row ${displayText(observed.id)}): ${mismatch}`,
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
    const rows = yield* fetchAllMirrorRows(context.client, context.projectId);
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
        `Mirror bijection verification OK: chain entries 1..${headSeq} \u2194 chain.* mirror rows match the mapping (AUDIT_SPEC §3.4)`,
      );
      return 0;
    }
    if (buckets.aheadRows > 0) {
      // 未検証の行が残る限り「OK」とは言わない(pullfrog 指摘 — 偽造行が
      // 未検証枠に恒久に居座る形を、成功終了で覆い隠さない)
      yield* io.logError(
        `Mirror verification incomplete: ${countNoun(buckets.aheadRows, "row")} newer than the local chain could not be verified in this run (this can happen when the chain grew right after the sync). Re-run maruhi audit verify — if this does not resolve, those mirror rows claim entries that do not exist on the chain (suspected forgery)`,
      );
    }
    for (const problem of problems) {
      yield* io.logError(`Mirror verification failure: ${problem}`);
    }
    if (problems.length > 0) {
      yield* io.logError(
        `Mirror verification found ${countNoun(problems.length, "problem")}. The audit log is server-managed data (AUDIT_SPEC §6) and these mismatches are evidence of server-side tampering or corruption — the distributed chain (signed and verified) is the truth; do not trust the audit log`,
      );
    }
    return 1;
  });
}
