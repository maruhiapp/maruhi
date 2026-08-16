// バージョンの単一の出所 = apps/cli/package.json。リリース時はタグとの一致を
// release workflow が検査する(docs/RELEASING.md)。
//
// **named import は必須**: default import に変えるとマニフェスト全体
// (scripts・依存ピン)が npm 配布物と全バイナリへ埋め込まれる(実測。
// npm-dist.test.ts が成果物側で固定)。import 箇所をこの 1 モジュールに
// 閉じ込めておくことで、危険な書き換えの当たり判定を 1 か所に保つ。

import { version } from "../package.json";

/** The CLI version reported by `maruhi --version`. */
export const CLI_VERSION: string = version;
