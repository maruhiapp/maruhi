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
