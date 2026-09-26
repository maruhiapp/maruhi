// 集約形 `var.read`(AUDIT_SPEC §3.3 — 値付き一括 pull ごとに環境単位 1 行、
// payload に返した変数の列挙)の表示導出。純関数のみ(unit テスト対象)。
//
// サーバー / CLI は @maruhi/core の auditReadVariablesOf を共有するが、Web は
// api-schema からの type-only import しか持たない(TCB を最小に保つ — types.ts
// 冒頭)ため、同じ解釈をここに置く。全値はサーバー申告であり検証はしない —
// 要素の受理条件は core と同一(variableId が文字列かつ epoch / version が整数)
// で、それ以外の要素は落とす(両者で件数・表示がずれないように)。
import type { AuditEvent } from "./types.ts";

/**
 * One variable listed by an aggregated `var.read` row, as reported by the
 * server. Entries without an integer epoch and version are dropped.
 */
export interface ListedReadVariable {
  readonly variableId: string;
  readonly epoch: number;
  readonly version: number;
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * 列挙の 1 要素の整形。@maruhi/core の auditReadVariablesOf と同じ受理条件
 * (variableId が文字列かつ epoch / version が整数)を満たさなければ落とす。
 */
function listedReadVariableOf(entry: unknown): ListedReadVariable | null {
  return isJsonRecord(entry) && isListedReadVariable(entry)
    ? { variableId: entry.variableId, epoch: entry.epoch, version: entry.version }
    : null;
}

/** 受理条件(variableId が文字列かつ epoch / version が整数 — core と同一)。 */
function isListedReadVariable(
  entry: Record<string, unknown>,
): entry is Record<string, unknown> & ListedReadVariable {
  return (
    typeof entry["variableId"] === "string" &&
    Number.isInteger(entry["epoch"]) &&
    Number.isInteger(entry["version"])
  );
}

/** payload の `variables` 列挙(配列でなければ null = 集約形ではない)。 */
function listedVariablesOf(
  payload: AuditEvent["payload"] | undefined,
): ReadonlyArray<ListedReadVariable> | null {
  const listed = payload?.["variables"];
  return Array.isArray(listed)
    ? listed.map(listedReadVariableOf).filter((entry) => entry !== null)
    : null;
}

/** 集約形 var.read の判定: イベント名 + variableId 欠落(旧形は列に持つ)+ 列挙。 */
export function aggregatedReadVariables(
  event: Pick<AuditEvent, "event" | "variableId" | "payload">,
): ReadonlyArray<ListedReadVariable> | null {
  return event.event === "var.read" && event.variableId === undefined
    ? listedVariablesOf(event.payload)
    : null;
}

/**
 * 集約形 var.read の payload から変数の列挙を除いた残り(authMethod 等)。空なら
 * null。列挙は折り畳みで見せ、残りは従来どおり記録どおりの JSON で見せる。
 */
export function payloadWithoutVariables(
  payload: NonNullable<AuditEvent["payload"]>,
): Readonly<Record<string, unknown>> | null {
  const { variables: _variables, ...rest } = payload;
  return Object.keys(rest).length === 0 ? null : rest;
}

/** 一覧の要約(英語 — ADR-0017): "read 3 variables" / "read 1 variable". */
export function readSummaryLabel(count: number): string {
  return `read ${count} ${count === 1 ? "variable" : "variables"}`;
}

/** 展開行の表示形: `var-id · epoch 1 · v 2`。 */
export function listedReadVariableLabel(variable: ListedReadVariable): string {
  return `${variable.variableId} · epoch ${variable.epoch} · v ${variable.version}`;
}
