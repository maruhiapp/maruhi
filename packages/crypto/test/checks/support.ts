// 環境非依存のチェック基盤。vitest(node / workerd / browser)と Bun 直接実行
// (test/run-in-bun.ts)の両方から同じチェックを呼ぶ(spike-c の構成を移植)。

import { decodeHex, encodeHex } from "../../src/index.ts";

export interface CheckResult {
  readonly name: string;
  readonly ok: boolean;
  readonly detail?: string;
}

export function toHex(bytes: Uint8Array): string {
  return encodeHex(bytes);
}

/** テストベクターの hex(信頼できる固定入力)をデコードする。不正なら例外 */
export function fromHex(s: string): Uint8Array {
  const bytes = decodeHex(s);
  if (bytes === null) {
    throw new Error(`test vector contains malformed hex: ${s.slice(0, 16)}…`);
  }
  return bytes;
}

/** チェック結果を積むための小さなコレクタ */
export class Checks {
  readonly results: CheckResult[] = [];

  push(name: string, ok: boolean, detail?: string): void {
    this.results.push({ name, ok, ...(detail === undefined ? {} : { detail }) });
  }
}

/**
 * 拒否理由の期待一致を検査し、一致した理由を行使済み集合へ記録する
 * (観点 7 — 理由空間の網羅固定。meta / value / manifest の negative ふるいで共用)。
 * `rejectedReason` は呼び出し側で「期待 kind で拒否された場合の reason、それ
 * 以外は undefined」に絞って渡す(kind の判別 union は層ごとに異なるため)。
 */
export function expectRejectedReason<R extends string>(
  c: Checks,
  name: string,
  rejectedReason: R | undefined,
  expectedReason: string | undefined,
  exercised: Set<R>,
  detail?: string,
): void {
  const rejected = rejectedReason !== undefined && rejectedReason === expectedReason;
  if (rejectedReason !== undefined && rejected) {
    exercised.add(rejectedReason);
  }
  c.push(name, rejected, detail);
}

/**
 * 理由 union の全メンバーが少なくとも 1 つの negative で実際に行使されたことを
 * 検査する(観点 7)。coverage の Record 型が union との同期をコンパイル時に
 * 強制するため、新しい拒否規則を実装したのに負例が無い、を型 + テストで捕まえる。
 */
export function reasonCoverageChecks<R extends string>(
  c: Checks,
  label: string,
  coverage: Record<R, true>,
  exercised: ReadonlySet<R>,
): void {
  // Object.keys は string[] を返すが、Record<R, true> のキーは R のみ(直接の
  // 変換は TS2352 になるため unknown を経由する)
  for (const reason of Object.keys(coverage) as unknown as readonly R[]) {
    c.push(`${label} reason coverage: ${reason} is exercised by a negative`, exercised.has(reason));
  }
}
