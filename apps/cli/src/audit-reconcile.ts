// `maruhi audit reconcile` — admin の監査突合(AUDIT_SPEC §6。2026-08-28
// セッション 38 = PR-M2 残余の解消)。
//
// 「発行時未検証の公証」(§6)の検証側: 全監査行から累積ハッシュ列を再計算し、
// 検証済みチェーン上の公証あり checkpoint それぞれについて
//   (a) 所属 — 公証ヘッドが再計算列に現れること
//   (b) 非後退 — 出現位置が公証 checkpoint 間で後退しないこと
//   (c) 位置下限 — 出現位置が直前 checkpoint(公証の有無を問わない)自身の
//       ミラー行(chain.checkpointed — chain_seq で同定)以上であること
//       (直前が存在しない初回は課さない — 受理検査と同一述語・同一基底)
// を検査する。違反は 2 区分で報告する(§6):
//   - 所属違反 (a) = 行改竄の証拠(公証済み接頭辞の事後改竄・削除)
//   - 位置違反 (b)(c) = 受理ポリシー(CRYPTO_SPEC §6.4 の位置下限)を執行しない
//     サーバーの証拠 — 陳腐化リプレイ(古い実在ヘッドの返し続け)が可能な状態
//
// 前提は実効権限 admin(チェーン role admin 以上 × トークンスコープ admin):
// 突合は §7 の `seq`(admin 可視)による欠番検査(欠番 = 削除の痕跡)を含み、
// 全行の取得もクラス 2 を含む admin 可視でなければ完全でない。role は検証済み
// ビュー、スコープは /auth/me から事前判定し、未満は明確なエラーにする
// (403 を踏まない — checkpoint 発行の事前判定と同じ規律)。
//
// 再計算の入力(AuditHeadRow.payloadText)はワイヤの payload(JSON)を
// JSON.stringify で直列化して得る。保存 TEXT はサーバー自身の JSON.stringify が
// 書いたものであり(audit-store.ts — 書き手はサーバーのみ)、識別子キーのみの
// オブジェクトは parse → stringify のラウンドトリップでバイト安定なため、
// 正直なサーバーでは再計算列が保存列と一致する。ここが食い違う場合、受信行は
// サーバーが列計算に使った行と異なる = 応答の自己矛盾であり、監査ログは
// サーバー管理データ(§6)なので改竄・破損の証拠として扱ってよい。

import { MAX_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
import { scopePermissionFor } from "@maruhi/core";
import type { AuditHeadRow, ChainEntry } from "@maruhi/crypto";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { WireAuditEvent } from "./audit.ts";
import { paginateAuditEvents } from "./audit.ts";
import { fetchAuditHead } from "./checkpoint.ts";
import type { CliServices, ProjectContextBase } from "./context.ts";
import { countNoun, displayText } from "./display.ts";
import type { CliError } from "./errors.ts";
import { cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";

/** 取得の進捗表示の間隔(ページ数)。巨大ログでの無反応・非停止を可視化する。 */
const FETCH_PROGRESS_PAGES = 50;

/** 違反の 2 区分(AUDIT_SPEC §6 の報告区分)+ 取得整合の失敗。 */
interface ReconcileViolation {
  readonly category: "row-tampering" | "acceptance-policy";
  readonly detail: string;
}

/**
 * 実効権限 admin(min(トークンスコープ, チェーン role) — AUTH_SPEC §9-2)の
 * 事前判定。未満は突合を始めずに明確なエラーで終える(§6 の突合は admin 可視の
 * `seq` と全行取得を要し、未満で走らせると欠番検査が可視性の穴を削除と誤断する)。
 */
function ensureEffectiveAdmin(context: ProjectContextBase): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const member = context.verified.state.members.get(context.session.userId);
    const role = member?.role;
    if (role !== "admin" && role !== "owner") {
      return yield* Effect.fail(
        cliError(
          "`maruhi audit reconcile` requires effective admin permission (AUDIT_SPEC §6): your chain role on this project is below admin, so the audit rows needed for the reconciliation (class-2 rows and the seq field) are not visible to you",
        ),
      );
    }
    const me = yield* context.client.auth.me({}).pipe(Effect.mapError(toCliError));
    if (me.tokenScopes !== undefined) {
      const granted = scopePermissionFor(me.tokenScopes, context.projectId);
      if (granted !== "admin") {
        return yield* Effect.fail(
          cliError(
            "`maruhi audit reconcile` requires effective admin permission (AUDIT_SPEC §6): this token's scope for the project is below admin. Re-run with an admin-scoped token",
          ),
        );
      }
    }
  });
}

/**
 * 全監査行の取得(§7 のページング — admin 可視・フィルタなし・新しい順)。
 *
 * 整合戦略(session-38 裁定 AJ): カーソルは行 id、重複 id と `seq` の非厳密減少
 * (ページ内・ページ間とも)をサーバー応答の自己矛盾として中止する。admin 応答の
 * `seq` は正の整数で厳密減少を強制するため、総行数は先頭ページの最大 seq に
 * 束縛され、ページングは必ず停止する。取得中に追記された行は先頭ページの
 * カーソルより新しく、以後のページに現れない — 取得集合は先頭ページ時点の
 * スナップショットとして閉じる(監査ヘッドの申告はこのスナップショットの
 * **前**に取るので、所属検査の母集合はスナップショットで覆われる)。
 */
/** 行ごとの整合検査(seq 必須・重複 id なし・seq 厳密減少)。null = 問題なし。 */
function reconcileRowProblem(
  row: WireAuditEvent,
  seenIds: ReadonlySet<string>,
  previousSeq: number | null,
): string | null {
  if (row.seq === undefined) {
    return `Audit row ${displayText(row.id)} carries no seq. The reconciliation needs the admin-visible seq field for the gap check (AUDIT_SPEC §7) — the server response is not the admin view this command verified permission for, so it contradicts itself`;
  }
  if (seenIds.has(row.id)) {
    return `Audit-log paging is not advancing (row ${displayText(row.id)} was returned twice) — the server response contradicts itself. Aborting the reconciliation`;
  }
  if (previousSeq !== null && row.seq >= previousSeq) {
    return `Audit rows are not in strictly descending seq order (seq ${row.seq} after ${previousSeq}) — the server response contradicts itself. Aborting the reconciliation`;
  }
  return null;
}

function fetchAllAuditRows(
  context: ProjectContextBase,
): Effect.Effect<readonly WireAuditEvent[], CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const rows: WireAuditEvent[] = [];
    const seenIds = new Set<string>();
    let previousSeq: number | null = null;
    let pages = 0;
    yield* paginateAuditEvents({
      pageLimit: MAX_AUDIT_EVENTS_PAGE_LIMIT,
      // 静的ページ上限なし: onRow の seq 厳密減少(正の整数)が総行数を先頭
      // ページの最大 seq に束縛し、停止性を担う(audit.ts の engine doc)
      bound: null,
      fetchPage: (before) =>
        Effect.gen(function* () {
          pages += 1;
          if (pages > 1 && (pages - 1) % FETCH_PROGRESS_PAGES === 0) {
            yield* io.log(`Fetched ${countNoun(rows.length, "audit row")} so far…`);
          }
          return yield* context.client.audit
            .events({
              params: { projectId: context.projectId },
              query: {
                limit: MAX_AUDIT_EVENTS_PAGE_LIMIT,
                ...(before === null ? {} : { before }),
              },
            })
            .pipe(
              Effect.mapError(toCliError),
              Effect.map((response) => response.events as readonly WireAuditEvent[]),
            );
        }),
      onRow: (row) => {
        const problem = reconcileRowProblem(row, seenIds, previousSeq);
        if (problem !== null) {
          return Effect.fail(cliError(problem));
        }
        seenIds.add(row.id);
        rows.push(row);
        previousSeq = row.seq ?? null;
        return Effect.void;
      },
    });
    return rows;
  });
}

/** ワイヤの optionalKey(欠落 = 保存 NULL)→ 計算入力の null。 */
function orNull<T>(value: T | undefined): T | null {
  return value === undefined ? null : value;
}

/** ワイヤ行 → 累積ハッシュ計算の入力形(AUDIT_SPEC §5.1 の 17 列)。 */
function toHeadRow(event: WireAuditEvent, seq: number): AuditHeadRow {
  return {
    seq,
    rowId: event.id,
    serverTs: event.serverTs,
    clientTs: orNull(event.clientTs),
    event: event.event,
    actorType: event.actor.type,
    actorUserId: orNull(event.actor.userId),
    actorKeyFingerprintHex: orNull(event.actor.keyFingerprintHex),
    actorApiTokenId: orNull(event.actor.apiTokenId),
    targetUserId: orNull(event.targetUserId),
    targetKeyFingerprintHex: orNull(event.targetKeyFingerprintHex),
    environmentId: orNull(event.environmentId),
    variableId: orNull(event.variableId),
    epoch: orNull(event.epoch),
    version: orNull(event.version),
    chainSeq: orNull(event.chainSeq),
    // 保存 TEXT の再構成(冒頭コメントのラウンドトリップ前提)。payload なし = NULL
    payloadText: event.payload === undefined ? null : JSON.stringify(event.payload),
  };
}

/** 再計算の結果: 位置索引(headHex → 監査 seq)と最終ヘッド。 */
interface RecomputedColumn {
  readonly positions: ReadonlyMap<string, number>;
  readonly finalHeadHex: string;
}

/**
 * 累積ハッシュ列の再計算(§5.1 — 正規実装は @maruhi/crypto。audit-head.json の
 * ベクターがサーバー実装と同一の h_n を固定する)。入力は seq 昇順の全行。
 */
function recomputeColumn(rows: readonly AuditHeadRow[]): Effect.Effect<RecomputedColumn, CliError> {
  return Effect.tryPromise({
    try: async () => {
      const positions = new Map<string, number>();
      let head = "";
      for (const row of rows) {
        const digest = await computeAuditRowDigest(row);
        const next = digest.ok
          ? await computeAuditHeadHash(SUITE_ID, head, row.seq, digest.value)
          : digest;
        if (!next.ok) {
          throw new Error(`recomputation failed at seq ${row.seq}: ${next.error.kind}`);
        }
        head = next.value;
        // SHA-256 の衝突は実際上ないが、万一の重複は先勝ち(最初の出現位置)
        if (!positions.has(head)) {
          positions.set(head, row.seq);
        }
      }
      return { positions, finalHeadHex: head };
    },
    // エラー値は seq と理由コードのみ(秘密を含まない)だが、規律どおり
    // 識別子だけの固定文面に写す
    catch: (error) =>
      cliError(
        `Failed to recompute the audit-head hash column (${error instanceof Error ? displayText(error.message) : "unknown"})`,
      ),
  });
}

/** 欠番検査(§6 — 欠番 = 削除の痕跡)。rows は seq 昇順。 */
function gapViolations(sortedSeqs: readonly number[]): readonly ReconcileViolation[] {
  const violations: ReconcileViolation[] = [];
  let expected = 1;
  for (const seq of sortedSeqs) {
    if (seq !== expected) {
      violations.push({
        category: "row-tampering",
        detail: `audit seq ${expected}${seq - 1 > expected ? `..${seq - 1}` : ""} is missing (the seq numbering is gapless by construction — AUDIT_SPEC §5.1 — so a gap is the trace of deleted rows)`,
      });
      expected = seq;
    }
    expected += 1;
  }
  return violations;
}

/** chain.checkpointed ミラー行の索引(chain_seq → 監査 seq の列)。 */
function checkpointMirrorIndex(rows: readonly WireAuditEvent[]): ReadonlyMap<number, number[]> {
  const index = new Map<number, number[]>();
  for (const row of rows) {
    if (row.event === "chain.checkpointed" && row.chainSeq !== undefined && row.seq !== undefined) {
      index.set(row.chainSeq, [...(index.get(row.chainSeq) ?? []), row.seq]);
    }
  }
  return index;
}

/** 公証位置と検査文脈(直前 checkpoint・直前の公証位置)。 */
interface NotarizedContext {
  readonly chainSeq: number;
  readonly position: number;
  readonly previousCheckpointChainSeq: number | null;
  readonly lastNotarized: { readonly chainSeq: number; readonly position: number } | null;
}

/** (b) 非後退: 公証 checkpoint 間で出現位置が後退しないこと。null = 問題なし。 */
function regressionViolation(context: NotarizedContext): ReconcileViolation | null {
  if (context.lastNotarized === null || context.position >= context.lastNotarized.position) {
    return null;
  }
  return {
    category: "acceptance-policy",
    detail: `checkpoint at chain seq ${context.chainSeq} notarizes audit position ${context.position}, behind the position ${context.lastNotarized.position} notarized by the earlier checkpoint at chain seq ${context.lastNotarized.chainSeq} (non-regression check (b))`,
  };
}

/**
 * (c) 位置下限: 出現位置が直前 checkpoint(公証の有無を問わない)自身の
 * ミラー行(chain.checkpointed — chain_seq で同定)以上であること。直前が
 * 存在しない初回は課さない(空虚に真)。ミラー行の欠落・重複は §3.4 の
 * 全単射の破れ = 行改竄側の証拠として報告する。
 */
function floorViolation(
  context: NotarizedContext,
  mirrors: ReadonlyMap<number, number[]>,
): ReconcileViolation | null {
  if (context.previousCheckpointChainSeq === null) {
    return null;
  }
  const mirrorSeqs = mirrors.get(context.previousCheckpointChainSeq) ?? [];
  const floor = mirrorSeqs[0];
  if (mirrorSeqs.length > 1) {
    return {
      category: "row-tampering",
      detail: `the checkpoint at chain seq ${context.previousCheckpointChainSeq} has ${countNoun(mirrorSeqs.length, "chain.checkpointed mirror row")} (mirrors are written exactly once per acceptance — duplicates are forged rows; run \`maruhi audit verify\`)`,
    };
  }
  if (floor === undefined) {
    return {
      category: "row-tampering",
      detail: `the checkpoint at chain seq ${context.previousCheckpointChainSeq} has no chain.checkpointed mirror row, so the position floor for the checkpoint at chain seq ${context.chainSeq} cannot be established (mirrors are written in the same transaction as acceptance — a missing mirror is evidence of a concealed deletion; run \`maruhi audit verify\`)`,
    };
  }
  if (context.position < floor) {
    return {
      category: "acceptance-policy",
      detail: `checkpoint at chain seq ${context.chainSeq} notarizes audit position ${context.position}, below the mirror row (audit seq ${floor}) of the immediately preceding checkpoint at chain seq ${context.previousCheckpointChainSeq} (position-floor check (c))`,
    };
  }
  return null;
}

/**
 * 公証あり checkpoint の所属 (a) + 位置 (b)(c) 検査(AUDIT_SPEC §6)。
 * entries は検証済みチェーン(seq 昇順)。
 */
function checkpointViolations(input: {
  readonly entries: readonly ChainEntry[];
  readonly positions: ReadonlyMap<string, number>;
  readonly mirrors: ReadonlyMap<number, number[]>;
}): { readonly violations: readonly ReconcileViolation[]; readonly notarized: number } {
  const violations: ReconcileViolation[] = [];
  let notarized = 0;
  let previousCheckpointChainSeq: number | null = null;
  let lastNotarized: { readonly chainSeq: number; readonly position: number } | null = null;
  for (const entry of input.entries) {
    if (entry.op !== "checkpoint") {
      continue;
    }
    const head = entry.payload.auditHeadHashHex;
    if (head !== "") {
      notarized += 1;
      const position = input.positions.get(head);
      if (position === undefined) {
        // (a) 所属違反: 公証時点でサーバーが「この累積ハッシュだった」と主張した
        // 事実は署名済み・チェーン上に固定されている。再計算列に現れない =
        // 公証済み接頭辞のどこかの行が後から改竄・削除された(§6)
        violations.push({
          category: "row-tampering",
          detail: `checkpoint at chain seq ${entry.seq} notarizes an audit head that does not appear in the column recomputed from the current rows (membership check (a))`,
        });
      } else {
        const context: NotarizedContext = {
          chainSeq: entry.seq,
          position,
          previousCheckpointChainSeq,
          lastNotarized,
        };
        violations.push(
          ...[regressionViolation(context), floorViolation(context, input.mirrors)].filter(
            (violation): violation is ReconcileViolation => violation !== null,
          ),
        );
        lastNotarized = { chainSeq: entry.seq, position };
      }
    }
    previousCheckpointChainSeq = entry.seq;
  }
  return { violations, notarized };
}

/** 申告ヘッドの所属検査(session-38 裁定 AK — 公証を待たない虚偽申告の検出)。 */
function declaredHeadViolations(
  declaredHeadHex: string,
  column: RecomputedColumn,
): readonly ReconcileViolation[] {
  if (declaredHeadHex === "" ? column.finalHeadHex === "" : column.positions.has(declaredHeadHex)) {
    return [];
  }
  return [
    {
      category: "row-tampering",
      detail:
        declaredHeadHex === ""
          ? "GET /audit-head declared an empty audit head, but the server returned audit rows (an empty declaration is only valid for an empty log)"
          : "the audit head declared by GET /audit-head does not appear in the column recomputed from the rows the server returned right after the declaration (the declaration and the rows contradict each other)",
    },
  ];
}

const CATEGORY_LABEL: Record<ReconcileViolation["category"], string> = {
  "row-tampering": "Row-tampering evidence",
  "acceptance-policy": "Acceptance-policy violation (stale-replay risk)",
};

/**
 * `maruhi audit reconcile`: admin の監査突合(AUDIT_SPEC §6)。実効権限 admin を
 * 事前判定 → 申告ヘッド取得 → 全行取得 → 欠番検査 → 累積列の再計算 → 公証あり
 * checkpoint の所属 (a) + 位置 (b)(c) 検査 → 2 区分で報告(違反あり = 終了コード 1)。
 */
export function auditReconcileOp(
  context: ProjectContextBase,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureEffectiveAdmin(context);
    // 申告は全行取得の**前**に取る(裁定 AK): 申告時点の列は取得スナップ
    // ショットの接頭辞なので、所属検査の母集合がスナップショットで必ず覆われる
    const declaredHeadHex = yield* fetchAuditHead(context.client, context.projectId);
    const rows = yield* fetchAllAuditRows(context);
    const ascending = [...rows].toSorted((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
    const seqs = ascending.map((row) => row.seq ?? 0);
    const gaps = gapViolations(seqs);
    if (gaps.length > 0) {
      // 欠番があると h_n の連鎖は欠番以降のすべてで食い違い、後段の所属検査が
      // 「全公証が違反」という誤解を招く派生報告になる。最強の証拠(削除の痕跡)
      // だけを報告して打ち切る(fail-closed — 誤帰属の量産をしない)
      for (const violation of gaps) {
        yield* io.logError(
          `Reconciliation failure [${CATEGORY_LABEL[violation.category]}]: ${violation.detail}`,
        );
      }
      yield* io.logError(
        "The audit log has seq gaps, so the cumulative-hash reconciliation cannot proceed past them. The audit log is server-managed data (AUDIT_SPEC §6) and a gap is evidence of server-side row deletion",
      );
      return 1;
    }
    const column = yield* recomputeColumn(ascending.map((row) => toHeadRow(row, row.seq ?? 0)));
    const checkpoints = checkpointViolations({
      entries: context.verified.entries,
      positions: column.positions,
      mirrors: checkpointMirrorIndex(rows),
    });
    const violations = [
      ...declaredHeadViolations(declaredHeadHex, column),
      ...checkpoints.violations,
    ];
    const summary = `${countNoun(rows.length, "audit row")} recomputed, ${countNoun(checkpoints.notarized, "notarized checkpoint")} checked against the verified chain`;
    if (violations.length === 0) {
      // 成功文言は証明した内容に忠実にする(pullfrog PR #102 レビュー対応):
      // 公証ゼロでは (a)(b)(c) は空虚に真で、実証したのは欠番なし + 申告所属
      // だけ。無条件の「checks passed」を出さない
      if (checkpoints.notarized === 0) {
        yield* io.log(
          `Audit reconciliation OK (nothing notarized yet): ${summary} — seq continuity and the declared head's membership verified; the checkpoint checks (a)(b)(c) are vacuous until an effective admin issues an audit-head-attested checkpoint (run \`maruhi project checkpoint\` — AUDIT_SPEC §6)`,
        );
        return 0;
      }
      yield* io.log(
        `Audit reconciliation OK: ${summary} — membership (a) and position (b)(c) checks passed (AUDIT_SPEC §6)`,
      );
      // §6 の明示的な残余: 公証済み接頭辞の外(最後の公証以降の行)は本突合の
      // 保護対象外 — 次の公証で前進する
      yield* logNote(
        "rows appended after the latest notarized checkpoint are outside the notarized prefix and are not covered until the next attested checkpoint (AUDIT_SPEC §6)",
      );
      return 0;
    }
    for (const violation of violations) {
      yield* io.logError(
        `Reconciliation failure [${CATEGORY_LABEL[violation.category]}]: ${violation.detail}`,
      );
    }
    yield* io.logError(
      `Audit reconciliation found ${countNoun(violations.length, "violation")} (${summary}). Row-tampering evidence means rows in the notarized prefix were altered or deleted after notarization; acceptance-policy violations mean the server accepted attestations it must reject (CRYPTO_SPEC §6.4), leaving it able to replay stale audit heads. The signed chain is the truth — do not trust this server's audit log (AUDIT_SPEC §6)`,
    );
    return 1;
  });
}
