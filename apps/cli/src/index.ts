// @maruhi/cli — Gunshi + Effect の `maruhi` / `mh` CLI。
// ディスクレス不変条件: シークレットの平文をディスクに書かない。.env 系ファイルの
// 生成機能を作らない。永続化は maruhi トークン・master 秘密鍵(OS キーチェーン)と
// 非機密設定のみ。

export { type CliServices, runCli } from "./cli.ts";
export { liveLayer } from "./live.ts";
